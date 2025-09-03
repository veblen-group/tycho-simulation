use std::{any::Any, collections::HashMap};

use alloy::primitives::{Sign, I256, U256};
use num_bigint::BigUint;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use tracing::trace;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::{Balances, GetAmountOutResult, ProtocolSim},
    },
    Bytes,
};

use super::enums::FeeAmount;
use crate::evm::protocol::{
    safe_math::{safe_add_u256, safe_sub_u256},
    u256_num::u256_to_biguint,
    utils::uniswap::{
        i24_be_bytes_to_i32, liquidity_math,
        sqrt_price_math::{get_amount0_delta, get_amount1_delta, sqrt_price_q96_to_f64},
        swap_math,
        tick_list::{TickInfo, TickList, TickListErrorKind},
        tick_math::{
            get_sqrt_ratio_at_tick, get_tick_at_sqrt_ratio, MAX_SQRT_RATIO, MAX_TICK,
            MIN_SQRT_RATIO, MIN_TICK,
        },
        StepComputation, SwapResults, SwapState,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniswapV3State {
    liquidity: u128,
    sqrt_price: U256,
    fee: FeeAmount,
    tick: i32,
    ticks: TickList,
}

impl UniswapV3State {
    /// Creates a new instance of `UniswapV3State`.
    ///
    /// # Arguments
    /// - `liquidity`: The initial liquidity of the pool.
    /// - `sqrt_price`: The square root of the current price.
    /// - `fee`: The fee tier for the pool.
    /// - `tick`: The current tick of the pool.
    /// - `ticks`: A vector of `TickInfo` representing the tick information for the pool.
    pub fn new(
        liquidity: u128,
        sqrt_price: U256,
        fee: FeeAmount,
        tick: i32,
        ticks: Vec<TickInfo>,
    ) -> Self {
        let spacing = UniswapV3State::get_spacing(fee);
        let tick_list = TickList::from(spacing, ticks);
        UniswapV3State { liquidity, sqrt_price, fee, tick, ticks: tick_list }
    }

    fn get_spacing(fee: FeeAmount) -> u16 {
        match fee {
            FeeAmount::Lowest => 1,
            FeeAmount::Low => 10,
            FeeAmount::MediumLow => 50,
            FeeAmount::Medium => 60,
            FeeAmount::MediumHigh => 100,
            FeeAmount::High => 200,
        }
    }

    fn swap(
        &self,
        zero_for_one: bool,
        amount_specified: I256,
        sqrt_price_limit: Option<U256>,
    ) -> Result<SwapResults, SimulationError> {
        if self.liquidity == 0 {
            return Err(SimulationError::RecoverableError("No liquidity".to_string()));
        }
        let price_limit = if let Some(limit) = sqrt_price_limit {
            limit
        } else if zero_for_one {
            safe_add_u256(MIN_SQRT_RATIO, U256::from(1u64))?
        } else {
            safe_sub_u256(MAX_SQRT_RATIO, U256::from(1u64))?
        };

        if zero_for_one {
            assert!(price_limit > MIN_SQRT_RATIO);
            assert!(price_limit < self.sqrt_price);
        } else {
            assert!(price_limit < MAX_SQRT_RATIO);
            assert!(price_limit > self.sqrt_price);
        }

        let exact_input = amount_specified > I256::from_raw(U256::from(0u64));

        let mut state = SwapState {
            amount_remaining: amount_specified,
            amount_calculated: I256::from_raw(U256::from(0u64)),
            sqrt_price: self.sqrt_price,
            tick: self.tick,
            liquidity: self.liquidity,
        };
        let mut gas_used = U256::from(130_000);

        while state.amount_remaining != I256::from_raw(U256::from(0u64)) &&
            state.sqrt_price != price_limit
        {
            let (mut next_tick, initialized) = match self
                .ticks
                .next_initialized_tick_within_one_word(state.tick, zero_for_one)
            {
                Ok((tick, init)) => (tick, init),
                Err(tick_err) => match tick_err.kind {
                    TickListErrorKind::TicksExeeded => {
                        let mut new_state = self.clone();
                        new_state.liquidity = state.liquidity;
                        new_state.tick = state.tick;
                        new_state.sqrt_price = state.sqrt_price;
                        return Err(SimulationError::InvalidInput(
                            "Ticks exceeded".into(),
                            Some(GetAmountOutResult::new(
                                u256_to_biguint(state.amount_calculated.abs().into_raw()),
                                u256_to_biguint(gas_used),
                                Box::new(new_state),
                            )),
                        ));
                    }
                    _ => return Err(SimulationError::FatalError("Unknown error".to_string())),
                },
            };

            next_tick = next_tick.clamp(MIN_TICK, MAX_TICK);

            let sqrt_price_next = get_sqrt_ratio_at_tick(next_tick)?;
            let (sqrt_price, amount_in, amount_out, fee_amount) = swap_math::compute_swap_step(
                state.sqrt_price,
                UniswapV3State::get_sqrt_ratio_target(sqrt_price_next, price_limit, zero_for_one),
                state.liquidity,
                state.amount_remaining,
                self.fee as u32,
            )?;
            state.sqrt_price = sqrt_price;

            let step = StepComputation {
                sqrt_price_start: state.sqrt_price,
                tick_next: next_tick,
                initialized,
                sqrt_price_next,
                amount_in,
                amount_out,
                fee_amount,
            };
            if exact_input {
                state.amount_remaining -= I256::checked_from_sign_and_abs(
                    Sign::Positive,
                    safe_add_u256(step.amount_in, step.fee_amount)?,
                )
                .unwrap();
                state.amount_calculated -=
                    I256::checked_from_sign_and_abs(Sign::Positive, step.amount_out).unwrap();
            } else {
                state.amount_remaining +=
                    I256::checked_from_sign_and_abs(Sign::Positive, step.amount_out).unwrap();
                state.amount_calculated += I256::checked_from_sign_and_abs(
                    Sign::Positive,
                    safe_add_u256(step.amount_in, step.fee_amount)?,
                )
                .unwrap();
            }
            if state.sqrt_price == step.sqrt_price_next {
                if step.initialized {
                    let liquidity_raw = self
                        .ticks
                        .get_tick(step.tick_next)
                        .unwrap()
                        .net_liquidity;
                    let liquidity_net = if zero_for_one { -liquidity_raw } else { liquidity_raw };
                    state.liquidity =
                        liquidity_math::add_liquidity_delta(state.liquidity, liquidity_net)?;
                }
                state.tick = if zero_for_one { step.tick_next - 1 } else { step.tick_next };
            } else if state.sqrt_price != step.sqrt_price_start {
                state.tick = get_tick_at_sqrt_ratio(state.sqrt_price)?;
            }
            gas_used = safe_add_u256(gas_used, U256::from(2000))?;
        }
        Ok(SwapResults {
            amount_calculated: state.amount_calculated,
            sqrt_price: state.sqrt_price,
            liquidity: state.liquidity,
            tick: state.tick,
            gas_used,
        })
    }

    fn get_sqrt_ratio_target(
        sqrt_price_next: U256,
        sqrt_price_limit: U256,
        zero_for_one: bool,
    ) -> U256 {
        let cond1 = if zero_for_one {
            sqrt_price_next < sqrt_price_limit
        } else {
            sqrt_price_next > sqrt_price_limit
        };

        if cond1 {
            sqrt_price_limit
        } else {
            sqrt_price_next
        }
    }
}

impl ProtocolSim for UniswapV3State {
    fn fee(&self) -> f64 {
        (self.fee as u32) as f64 / 1_000_000.0
    }

    fn spot_price(&self, a: &Token, b: &Token) -> Result<f64, SimulationError> {
        if a < b {
            Ok(sqrt_price_q96_to_f64(self.sqrt_price, a.decimals, b.decimals))
        } else {
            Ok(1.0f64 / sqrt_price_q96_to_f64(self.sqrt_price, b.decimals, a.decimals))
        }
    }

    fn get_amount_out(
        &self,
        amount_in: BigUint,
        token_a: &Token,
        token_b: &Token,
    ) -> Result<GetAmountOutResult, SimulationError> {
        let zero_for_one = token_a < token_b;
        let amount_specified = I256::checked_from_sign_and_abs(
            Sign::Positive,
            U256::from_be_slice(&amount_in.to_bytes_be()),
        )
        .ok_or_else(|| {
            SimulationError::InvalidInput("I256 overflow: amount_in".to_string(), None)
        })?;

        let result = self.swap(zero_for_one, amount_specified, None)?;

        trace!(?amount_in, ?token_a, ?token_b, ?zero_for_one, ?result, "V3 SWAP");
        let mut new_state = self.clone();
        new_state.liquidity = result.liquidity;
        new_state.tick = result.tick;
        new_state.sqrt_price = result.sqrt_price;

        Ok(GetAmountOutResult::new(
            u256_to_biguint(
                result
                    .amount_calculated
                    .abs()
                    .into_raw(),
            ),
            u256_to_biguint(result.gas_used),
            Box::new(new_state),
        ))
    }

    fn get_limits(
        &self,
        token_in: Bytes,
        token_out: Bytes,
    ) -> Result<(BigUint, BigUint), SimulationError> {
        // If the pool has no liquidity, return zeros for both limits
        if self.liquidity == 0 {
            return Ok((BigUint::zero(), BigUint::zero()));
        }

        let zero_for_one = token_in < token_out;
        let mut current_tick = self.tick;
        let mut current_sqrt_price = self.sqrt_price;
        let mut current_liquidity = self.liquidity;
        let mut total_amount_in = U256::from(0u64);
        let mut total_amount_out = U256::from(0u64);

        // Iterate through all ticks in the direction of the swap
        // Continues until there is no more liquidity in the pool or no more ticks to process
        while let Ok((tick, initialized)) = self
            .ticks
            .next_initialized_tick_within_one_word(current_tick, zero_for_one)
        {
            // Clamp the tick value to ensure it's within valid range
            let next_tick = tick.clamp(MIN_TICK, MAX_TICK);

            // Calculate the sqrt price at the next tick boundary
            let sqrt_price_next = get_sqrt_ratio_at_tick(next_tick)?;

            // Calculate the amount of tokens swapped when moving from current_sqrt_price to
            // sqrt_price_next. Direction determines which token is being swapped in vs out
            let (amount_in, amount_out) = if zero_for_one {
                let amount0 = get_amount0_delta(
                    sqrt_price_next,
                    current_sqrt_price,
                    current_liquidity,
                    true,
                )?;
                let amount1 = get_amount1_delta(
                    sqrt_price_next,
                    current_sqrt_price,
                    current_liquidity,
                    false,
                )?;
                (amount0, amount1)
            } else {
                let amount0 = get_amount0_delta(
                    sqrt_price_next,
                    current_sqrt_price,
                    current_liquidity,
                    false,
                )?;
                let amount1 = get_amount1_delta(
                    sqrt_price_next,
                    current_sqrt_price,
                    current_liquidity,
                    true,
                )?;
                (amount1, amount0)
            };

            // Accumulate total amounts for this tick range
            total_amount_in = safe_add_u256(total_amount_in, amount_in)?;
            total_amount_out = safe_add_u256(total_amount_out, amount_out)?;

            // If this tick is "initialized" (meaning its someone's position boundary), update the
            // liquidity when crossing it
            // For zero_for_one, liquidity is removed when crossing a tick
            // For one_for_zero, liquidity is added when crossing a tick
            if initialized {
                let liquidity_raw = self
                    .ticks
                    .get_tick(next_tick)
                    .unwrap()
                    .net_liquidity;
                let liquidity_delta = if zero_for_one { -liquidity_raw } else { liquidity_raw };
                current_liquidity =
                    liquidity_math::add_liquidity_delta(current_liquidity, liquidity_delta)?;
            }

            // Move to the next tick position
            current_tick = if zero_for_one { next_tick - 1 } else { next_tick };
            current_sqrt_price = sqrt_price_next;
        }

        Ok((u256_to_biguint(total_amount_in), u256_to_biguint(total_amount_out)))
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        // apply attribute changes
        if let Some(liquidity) = delta
            .updated_attributes
            .get("liquidity")
        {
            // This is a hotfix because if the liquidity has never been updated after creation, it's
            // currently encoded as H256::zero(), therefore, we can't decode this as u128.
            // We can remove this once it has been fixed on the tycho side.
            let liq_16_bytes = if liquidity.len() == 32 {
                // Make sure it only happens for 0 values, otherwise error.
                if liquidity == &Bytes::zero(32) {
                    Bytes::from([0; 16])
                } else {
                    return Err(TransitionError::DecodeError(format!(
                        "Liquidity bytes too long for {liquidity}, expected 16",
                    )));
                }
            } else {
                liquidity.clone()
            };

            self.liquidity = u128::from(liq_16_bytes);
        }
        if let Some(sqrt_price) = delta
            .updated_attributes
            .get("sqrt_price_x96")
        {
            self.sqrt_price = U256::from_be_slice(sqrt_price);
        }
        if let Some(tick) = delta.updated_attributes.get("tick") {
            // This is a hotfix because if the tick has never been updated after creation, it's
            // currently encoded as H256::zero(), therefore, we can't decode this as i32.
            // We can remove this once it has been fixed on the tycho side.
            let ticks_4_bytes = if tick.len() == 32 {
                // Make sure it only happens for 0 values, otherwise error.
                if tick == &Bytes::zero(32) {
                    Bytes::from([0; 4])
                } else {
                    return Err(TransitionError::DecodeError(format!(
                        "Tick bytes too long for {tick}, expected 4"
                    )));
                }
            } else {
                tick.clone()
            };
            self.tick = i24_be_bytes_to_i32(&ticks_4_bytes);
        }

        // apply tick changes
        for (key, value) in delta.updated_attributes.iter() {
            // tick liquidity keys are in the format "tick/{tick_index}/net_liquidity"
            if key.starts_with("ticks/") {
                let parts: Vec<&str> = key.split('/').collect();
                self.ticks.set_tick_liquidity(
                    parts[1]
                        .parse::<i32>()
                        .map_err(|err| TransitionError::DecodeError(err.to_string()))?,
                    i128::from(value.clone()),
                )
            }
        }
        // delete ticks - ignores deletes for attributes other than tick liquidity
        for key in delta.deleted_attributes.iter() {
            // tick liquidity keys are in the format "tick/{tick_index}/net_liquidity"
            if key.starts_with("tick/") {
                let parts: Vec<&str> = key.split('/').collect();
                self.ticks.set_tick_liquidity(
                    parts[1]
                        .parse::<i32>()
                        .map_err(|err| TransitionError::DecodeError(err.to_string()))?,
                    0,
                )
            }
        }
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn ProtocolSim> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn eq(&self, other: &dyn ProtocolSim) -> bool {
        if let Some(other_state) = other
            .as_any()
            .downcast_ref::<UniswapV3State>()
        {
            self.liquidity == other_state.liquidity &&
                self.sqrt_price == other_state.sqrt_price &&
                self.fee == other_state.fee &&
                self.tick == other_state.tick &&
                self.ticks == other_state.ticks
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        fs,
        path::Path,
        str::FromStr,
    };

    use num_bigint::ToBigUint;
    use num_traits::FromPrimitive;
    use serde_json::Value;
    use tycho_client::feed::synchronizer::ComponentWithState;
    use tycho_common::{hex_bytes::Bytes, models::Chain};

    use super::*;
    use crate::protocol::models::TryFromWithBlock;

    #[test]
    fn test_get_amount_out_full_range_liquidity() {
        let token_x = Token::new(
            &Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap(),
            "X",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let token_y = Token::new(
            &Bytes::from_str("0xf1ca9cb74685755965c7458528a36934df52a3ef").unwrap(),
            "Y",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let pool = UniswapV3State::new(
            8330443394424070888454257,
            U256::from_str("188562464004052255423565206602").unwrap(),
            FeeAmount::Medium,
            17342,
            vec![TickInfo::new(0, 0), TickInfo::new(46080, 0)],
        );
        let sell_amount = BigUint::from_str("11_000_000000000000000000").unwrap();
        let expected = BigUint::from_str("61927070842678722935941").unwrap();

        let res = pool
            .get_amount_out(sell_amount, &token_x, &token_y)
            .unwrap();

        assert_eq!(res.amount, expected);
    }

    struct SwapTestCase {
        symbol: &'static str,
        sell: BigUint,
        exp: BigUint,
    }

    #[test]
    fn test_get_amount_out() {
        let wbtc = Token::new(
            &Bytes::from_str("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599").unwrap(),
            "WBTC",
            8,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let weth = Token::new(
            &Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(),
            "WETH",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let pool = UniswapV3State::new(
            377952820878029838,
            U256::from_str("28437325270877025820973479874632004").unwrap(),
            FeeAmount::Low,
            255830,
            vec![
                TickInfo::new(255760, 1759015528199933i128),
                TickInfo::new(255770, 6393138051835308i128),
                TickInfo::new(255780, 228206673808681i128),
                TickInfo::new(255820, 1319490609195820i128),
                TickInfo::new(255830, 678916926147901i128),
                TickInfo::new(255840, 12208947683433103i128),
                TickInfo::new(255850, 1177970713095301i128),
                TickInfo::new(255860, 8752304680520407i128),
                TickInfo::new(255880, 1486478248067104i128),
                TickInfo::new(255890, 1878744276123248i128),
                TickInfo::new(255900, 77340284046725227i128),
            ],
        );
        let cases = vec![
            SwapTestCase {
                symbol: "WBTC",
                sell: 500000000.to_biguint().unwrap(),
                exp: BigUint::from_str("64352395915550406461").unwrap(),
            },
            SwapTestCase {
                symbol: "WBTC",
                sell: 550000000.to_biguint().unwrap(),
                exp: BigUint::from_str("70784271504035662865").unwrap(),
            },
            SwapTestCase {
                symbol: "WBTC",
                sell: 600000000.to_biguint().unwrap(),
                exp: BigUint::from_str("77215534856185613494").unwrap(),
            },
            SwapTestCase {
                symbol: "WBTC",
                sell: BigUint::from_str("1000000000").unwrap(),
                exp: BigUint::from_str("128643569649663616249").unwrap(),
            },
            SwapTestCase {
                symbol: "WBTC",
                sell: BigUint::from_str("3000000000").unwrap(),
                exp: BigUint::from_str("385196519076234662939").unwrap(),
            },
            SwapTestCase {
                symbol: "WETH",
                sell: BigUint::from_str("64000000000000000000").unwrap(),
                exp: BigUint::from_str("496294784").unwrap(),
            },
            SwapTestCase {
                symbol: "WETH",
                sell: BigUint::from_str("70000000000000000000").unwrap(),
                exp: BigUint::from_str("542798479").unwrap(),
            },
            SwapTestCase {
                symbol: "WETH",
                sell: BigUint::from_str("77000000000000000000").unwrap(),
                exp: BigUint::from_str("597047757").unwrap(),
            },
            SwapTestCase {
                symbol: "WETH",
                sell: BigUint::from_str("128000000000000000000").unwrap(),
                exp: BigUint::from_str("992129037").unwrap(),
            },
            SwapTestCase {
                symbol: "WETH",
                sell: BigUint::from_str("385000000000000000000").unwrap(),
                exp: BigUint::from_str("2978713582").unwrap(),
            },
        ];

        for case in cases {
            let (token_a, token_b) =
                if case.symbol == "WBTC" { (&wbtc, &weth) } else { (&weth, &wbtc) };
            let res = pool
                .get_amount_out(case.sell, token_a, token_b)
                .unwrap();

            assert_eq!(res.amount, case.exp);
        }
    }

    #[test]
    fn test_err_with_partial_trade() {
        let dai = Token::new(
            &Bytes::from_str("0x6b175474e89094c44da98b954eedeac495271d0f").unwrap(),
            "DAI",
            18,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let usdc = Token::new(
            &Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
            "USDC",
            6,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let pool = UniswapV3State::new(
            73015811375239994,
            U256::from_str("148273042406850898575413").unwrap(),
            FeeAmount::High,
            -263789,
            vec![
                TickInfo::new(-269600, 3612326326695492i128),
                TickInfo::new(-268800, 1487613939516867i128),
                TickInfo::new(-267800, 1557587121322546i128),
                TickInfo::new(-267400, 424592076717375i128),
                TickInfo::new(-267200, 11691597431643916i128),
                TickInfo::new(-266800, -218742815100986i128),
                TickInfo::new(-266600, 1118947532495477i128),
                TickInfo::new(-266200, 1233064286622365i128),
                TickInfo::new(-265000, 4252603063356107i128),
                TickInfo::new(-263200, -351282010325232i128),
                TickInfo::new(-262800, -2352011819117842i128),
                TickInfo::new(-262600, -424592076717375i128),
                TickInfo::new(-262200, -11923662433672566i128),
                TickInfo::new(-261600, -2432911749667741i128),
                TickInfo::new(-260200, -4032727022572273i128),
                TickInfo::new(-260000, -22889492064625028i128),
                TickInfo::new(-259400, -1557587121322546i128),
                TickInfo::new(-259200, -1487613939516867i128),
                TickInfo::new(-258400, -400137022888262i128),
            ],
        );
        let amount_in = BigUint::from_str("50000000000").unwrap();
        let exp = BigUint::from_str("6820591625999718100883").unwrap();

        let err = pool
            .get_amount_out(amount_in, &usdc, &dai)
            .unwrap_err();

        match err {
            SimulationError::InvalidInput(ref _err, ref amount_out_result) => {
                match amount_out_result {
                    Some(amount_out_result) => {
                        assert_eq!(amount_out_result.amount, exp);
                        let new_state = amount_out_result
                            .new_state
                            .as_any()
                            .downcast_ref::<UniswapV3State>()
                            .unwrap();
                        assert_ne!(new_state.tick, pool.tick);
                        assert_ne!(new_state.liquidity, pool.liquidity);
                    }
                    _ => panic!("Partial amount out result is None. Expected partial result."),
                }
            }
            _ => panic!("Test failed: was expecting a SimulationError::InsufficientData"),
        }
    }

    #[test]
    fn test_delta_transition() {
        let mut pool = UniswapV3State::new(
            1000,
            U256::from_str("1000").unwrap(),
            FeeAmount::Low,
            100,
            vec![TickInfo::new(255760, 10000), TickInfo::new(255900, -10000)],
        );
        let attributes: HashMap<String, Bytes> = [
            ("liquidity".to_string(), Bytes::from(2000_u64.to_be_bytes().to_vec())),
            ("sqrt_price_x96".to_string(), Bytes::from(1001_u64.to_be_bytes().to_vec())),
            ("tick".to_string(), Bytes::from(120_i32.to_be_bytes().to_vec())),
            (
                "ticks/-255760/net_liquidity".to_string(),
                Bytes::from(10200_u64.to_be_bytes().to_vec()),
            ),
            (
                "ticks/255900/net_liquidity".to_string(),
                Bytes::from(9800_u64.to_be_bytes().to_vec()),
            ),
        ]
        .into_iter()
        .collect();
        let delta = ProtocolStateDelta {
            component_id: "State1".to_owned(),
            updated_attributes: attributes,
            deleted_attributes: HashSet::new(),
        };

        pool.delta_transition(delta, &HashMap::new(), &Balances::default())
            .unwrap();

        assert_eq!(pool.liquidity, 2000);
        assert_eq!(pool.sqrt_price, U256::from(1001));
        assert_eq!(pool.tick, 120);
        assert_eq!(
            pool.ticks
                .get_tick(-255760)
                .unwrap()
                .net_liquidity,
            10200
        );
        assert_eq!(
            pool.ticks
                .get_tick(255900)
                .unwrap()
                .net_liquidity,
            9800
        );
    }

    #[tokio::test]
    async fn test_get_limits() {
        let project_root = env!("CARGO_MANIFEST_DIR");
        let asset_path =
            Path::new(project_root).join("tests/assets/decoder/uniswap_v3_snapshot.json");
        let json_data = fs::read_to_string(asset_path).expect("Failed to read test asset");
        let data: Value = serde_json::from_str(&json_data).expect("Failed to parse JSON");

        let state: ComponentWithState = serde_json::from_value(data)
            .expect("Expected json to match ComponentWithState structure");

        let usv3_state = UniswapV3State::try_from_with_header(
            state,
            Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .await
        .unwrap();

        let t0 = Token::new(
            &Bytes::from_str("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599").unwrap(),
            "WBTC",
            8,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let t1 = Token::new(
            &Bytes::from_str("0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf").unwrap(),
            "cbBTC",
            8,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        let res = usv3_state
            .get_limits(t0.address.clone(), t1.address.clone())
            .unwrap();

        assert_eq!(&res.0, &BigUint::from_u128(20358481906554983980330155).unwrap()); // Crazy amount because of this tick: "ticks/-887272/net-liquidity": "0x10d73d"

        let out = usv3_state
            .get_amount_out(res.0, &t0, &t1)
            .expect("swap for limit in didn't work");

        assert_eq!(&res.1, &out.amount);
    }
}

#[cfg(test)]
mod tests_forks {
    use std::{fs, path::Path, str::FromStr};

    use serde_json::Value;
    use tycho_client::feed::synchronizer::ComponentWithState;
    use tycho_common::models::Chain;

    use super::*;
    use crate::protocol::models::TryFromWithBlock;

    #[tokio::test]
    async fn test_pancakeswap_get_amount_out() {
        let project_root = env!("CARGO_MANIFEST_DIR");
        let asset_path =
            Path::new(project_root).join("tests/assets/decoder/pancakeswap_v3_snapshot.json");
        let json_data = fs::read_to_string(asset_path).expect("Failed to read test asset");
        let data: Value = serde_json::from_str(&json_data).expect("Failed to parse JSON");

        let state: ComponentWithState = serde_json::from_value(data)
            .expect("Expected json to match ComponentWithState structure");

        let pool_state = UniswapV3State::try_from_with_header(
            state,
            Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .await
        .unwrap();

        let usdc = Token::new(
            &Bytes::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap(),
            "USDC",
            6,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );
        let usdt = Token::new(
            &Bytes::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7").unwrap(),
            "USDT",
            6,
            0,
            &[Some(10_000)],
            Chain::Ethereum,
            100,
        );

        // Swap from https://etherscan.io/tx/0x641b1e98990ae49fd00157a29e1530ff6403706b2864aa52b1c30849ce020b2c#eventlog
        let res = pool_state
            .get_amount_out(BigUint::from_str("5976361609").unwrap(), &usdt, &usdc)
            .unwrap();

        assert_eq!(res.amount, BigUint::from_str("5975901673").unwrap());
    }
}
