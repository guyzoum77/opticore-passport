import {VerifyFunction} from "passport-local";


export interface VerifyLocalStrategyInterface extends VerifyFunction {
    (fetchUserByEmail: (email: string) => Promise<any>,
     email: string,
     hashedPassword: string,
     done: any,
     salt: any,
     plainPassword: any,
     algorithmHash: any,
     iteration: number,
     keyLength: number,
     encode: BufferEncoding | undefined
    ): void;
}