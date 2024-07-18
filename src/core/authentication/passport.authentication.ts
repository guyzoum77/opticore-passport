import {PassportStrategy} from "../strategies/passport.strategy";
import {HashPasswordService} from "opticore-hashing-password";

export class PassportAuthentication {
    public hashingService: HashPasswordService = new HashPasswordService();
    public publicRSAKeyPair: string;

    constructor(hashPasswordService: HashPasswordService, publicRSAKey: string) {
        this.hashingService   = hashPasswordService;
        this.publicRSAKeyPair = publicRSAKey
    }

    public initializeLocalStrategyAuthWithEmail(fetchUserByEmail: (email: string) => Promise<any>, email: string,
                                       hashedPassword: string, done: any, salt: any, plainPassword: any,
                                       algorithmHash: any, iteration: number, keyLength: number,
                                       encode: BufferEncoding | undefined) {
        const passportStr: PassportStrategy = new PassportStrategy(this.publicRSAKeyPair);
        passportStr.useLocalStrategyByEmail(
            fetchUserByEmail,
            email,
            hashedPassword,
            done,
            salt,
            plainPassword,
            algorithmHash,
            iteration,
            keyLength,
            encode
        ).then(
            () => {},
            () => {},
        ).catch(() => {
            
        });
    }
}