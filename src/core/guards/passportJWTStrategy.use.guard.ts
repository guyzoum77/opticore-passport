import passport, {Strategy} from "passport";
import {JwtFromRequestFunction} from "passport-jwt";
import {JwtPayload} from "jsonwebtoken";

type TypeStrategy<T, U, VerifyFunction> = { new (params: U, callback: VerifyFunction): T}

export function PassportJWTStrategyUse<T extends Strategy, U, VerifyFunction>(
    name: string, 
    Strategy: TypeStrategy<T, U, VerifyFunction>, 
    params: U, 
    callback: VerifyFunction) {
    passport.use(name, new Strategy(params, callback));
}