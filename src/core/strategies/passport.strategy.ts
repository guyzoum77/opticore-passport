import {constants} from "http2";
import { MessageUtils as msg} from "../utils/message.utils";
import { LogMessageCore as log} from "opticore-console-log-message";
import {HashPasswordService} from "opticore-hashing-password";
import {JwtPayload} from "jsonwebtoken";
import {PassportLocalStrategyUse} from "../guards/passportLocalStrategy.use.guard";
import {Strategy as LocalStrategy} from "passport-local";
import {Strategy as JwtStr, StrategyOptions, ExtractJwt, StrategyOptionsWithSecret} from 'passport-jwt';
import {VerifyLocalStrategyInterface} from "../interfaces/verifyLocalStrategy.interface";
import {PassportJWTStrategyUse} from "../guards/passportJWTStrategy.use.guard";



/**
 *
 */
export class PassportStrategy {
    public hashingService: HashPasswordService = new HashPasswordService();
    public errorCode: number = constants.HTTP_STATUS_BAD_REQUEST;
    public publicRSAKeyPair: string;

    constructor(hashPasswordService: HashPasswordService, publicRSAKey: string) {
        this.hashingService   = hashPasswordService;
        this.publicRSAKeyPair = publicRSAKey
    }

    /**
     *
     * @param hashedPassword
     * @param salt
     * @param plainPassword
     * @param algorithmHash
     * @param iteration
     * @param keyLength
     * @param encode
     * @protected
     */
    protected async verifyHashPassword(hashedPassword: string, salt: any, plainPassword: any,
                                   algorithmHash: any, iteration: number, keyLength: number,
                                   encode: BufferEncoding | undefined): Promise<boolean> {
        return await this.hashingService.verifyHashPassword(
            hashedPassword, salt, plainPassword, algorithmHash, iteration, keyLength, encode
        );
    }

    /**
     *
     * @param err
     * @param actionTitle
     * @param done
     * @protected
     */
    protected catchError(err: any, actionTitle: any, done: any) {
        log.errorSpecified(msg.passportError, actionTitle, err.name, err.code, "Error", err.message, this.errorCode);
        return done(null, false, { message: err.message });
    }

    /**
     *
     * @param fetchUserByEmail
     * @param email
     * @param hashedPassword
     * @param done
     * @param salt
     * @param plainPassword
     * @param algorithmHash
     * @param iteration
     * @param keyLength
     * @param encode
     *
     * Return
     */
    public async validateLocalStrategy(fetchUserByEmail: (email: string) => Promise<any>, email: string,
                                       hashedPassword: string, done: any, salt: any, plainPassword: any,
                                       algorithmHash: any, iteration: number, keyLength: number,
                                       encode: BufferEncoding | undefined): Promise<any> {
        await fetchUserByEmail(email).then(async(user: any): Promise<any> => {
            if (!user) {
                log.error(msg.passportError, msg.localStrategyUserNotFound, msg.userNotFound, constants.HTTP_STATUS_NOT_FOUND);
                return done(null, false, { message: msg.userNotFound });
            }

            !await this.verifyHashPassword(hashedPassword, salt, plainPassword, algorithmHash, iteration, keyLength, encode)
                ? (() => { return done(null, false, { message: msg.wrongPassword }); })()
                : (() => { return done(null, user); })();

        }).catch((err: any): void => {
            this.catchError(err, msg.localStrategyUserNotFound, this.errorCode);
        });
    }


    /**
     *
     * @param fetchIUserById
     * @param payload
     * @param done
     * @param hashedPassword
     * @param salt
     * @param plainPassword
     * @param algorithmHash
     * @param iteration
     * @param keyLength
     * @param encode
     */
    public async validateJwtStrategy(fetchIUserById: (userId: string) => Promise<any>, payload: JwtPayload, done: any,
                                     hashedPassword: string, salt: any, plainPassword: any,
                                     algorithmHash: any, iteration: number, keyLength: number,
                                     encode: BufferEncoding | undefined): Promise<any> {
        const statusNotFound: number = constants.HTTP_STATUS_NOT_FOUND
        try {
            let user;
            if (!payload) {
                return log.error(msg.passportError, msg.jwtStrategyPayloadNotFound, msg.userNotFound, statusNotFound);
            } else if (payload && payload.sub === undefined) {
                return log.error(msg.passportError, "Undefined", msg.userNotFound, statusNotFound);
            } else {
                user = await fetchIUserById(payload.sub!);
            }

            !await this.verifyHashPassword(hashedPassword, salt, plainPassword, algorithmHash, iteration, keyLength, encode)
                ? (() => { return done(null, false, { message: msg.wrongPassword }); })()
                : (() => { return done(null, user); })();

        } catch (err: any) {
            this.catchError(err, msg.jwtStrategyUserNotFound, this.errorCode);
        }
    }


    /**
     * 
     * @param fetchUserByEmail 
     * @param email 
     * @param hashedPassword 
     * @param done 
     * @param salt 
     * @param plainPassword 
     * @param algorithmHash 
     * @param iteration 
     * @param keyLength 
     * @param encode 
     * @returns 
     */
    public async useLocalStrategy(fetchUserByEmail: (email: string) => Promise<any>, email: string,
                                  hashedPassword: string, done: any, salt: any, plainPassword: any,
                                  algorithmHash: any, iteration: number, keyLength: number,
                                  encode: BufferEncoding | undefined) {
        return PassportLocalStrategyUse<LocalStrategy, Object, VerifyLocalStrategyInterface>(
            "local",
            LocalStrategy,
            {
                username: process.env.PASSPORT_USERNAME,
                password: process.env.PASSPORT_PASSWORD
            },
            await this.validateLocalStrategy(
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
            )
        );
    }


    /**
     * 
     * @param fetchIUserById 
     * @param payload 
     * @param done 
     * @param hashedPassword 
     * @param salt 
     * @param plainPassword 
     * @param algorithmHash 
     * @param iteration 
     * @param keyLength 
     * @param encode 
     * @returns 
     */
    public useJwtStrategy(fetchIUserById: (userId: string) => Promise<any>,
                                payload: JwtPayload,
                                done: any,
                                hashedPassword: string,
                                salt: any,
                                plainPassword: any,
                                algorithmHash: any,
                                iteration: number,
                                keyLength: number,
                                encode: (BufferEncoding | undefined)) {
        return PassportJWTStrategyUse<JwtStr, StrategyOptionsWithSecret, (payload: JwtPayload, done: any) => Promise<JwtPayload>>(
            "jwt", 
            JwtStr,
            {
                jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
                secretOrKey: this.publicRSAKeyPair,
            },
            async (payload: JwtPayload, done: any) : Promise<any> => {
                this.validateJwtStrategy(
                    fetchIUserById,
                    payload,
                    done,
                    hashedPassword,
                    salt,
                    plainPassword,
                    algorithmHash,
                    iteration,
                    keyLength,
                    encode
                )
            }
        );
    }
}