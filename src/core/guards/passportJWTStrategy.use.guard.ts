import passport, {Strategy} from "passport";
import {JwtFromRequestFunction} from "passport-jwt";
import {JwtPayload} from "jsonwebtoken";

type TypeStrategy<T, U, VerifyFunction> = { new (params: U, callback: VerifyFunction): T}

export function PassportJWTStrategyUse<T extends Strategy, U, VerifyFunction>(
    name: string,
    Strategy: TypeStrategy<T, U, VerifyFunction>,
    params: { jwtFromRequest: JwtFromRequestFunction; secretOrKey: any },
    callback: (
        fetchIUserById: (userId: string) => Promise<any>, 
        payload: JwtPayload, 
        done: any, 
        hashedPassword: string,
        salt: any,
        plainPassword: any,
        algorithmHash: any, 
        iteration: number, 
        keyLength: number, 
        encode: (BufferEncoding | undefined)
    ) => Promise<void>) {
    return passport.use(name, new Strategy(params, callback));
}