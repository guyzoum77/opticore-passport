import passport, {Strategy} from "passport";

type TypeStrategy<T, U, VerifyFunction> = { new (params: U, callback: VerifyFunction): T}

export function PassportJWTStrategyUse<T extends Strategy, U, VerifyFunction>(
    name: string, 
    Strategy: TypeStrategy<T, U, VerifyFunction>, 
    params: U, 
    callback: VerifyFunction) {
    passport.use(name, new Strategy(params, callback));
}