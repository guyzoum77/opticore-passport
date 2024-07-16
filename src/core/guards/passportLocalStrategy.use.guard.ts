import passport, {Strategy} from "passport";

type TypeStrategy<T, U, VerifyFunctionInterface> = { new (params: U, callback: VerifyFunctionInterface): T}

export function PassportLocalStrategyUse<T extends Strategy, U, VerifyFunctionInterface>(
    name: string,
    Strategy: TypeStrategy<T, U, VerifyFunctionInterface>,
    params: U,
    callback: (
        fetchUserByEmail: (email: string) => Promise<any>,
        email: string,
        hashedPassword: string,
        done: any,
        salt: any,
        plainPassword: any,
        algorithmHash: any,
        iteration: number,
        keyLength: number,
        encode: (BufferEncoding | undefined)
    ) => Promise<any>) {
    passport.use(name, new Strategy(params, callback));
}