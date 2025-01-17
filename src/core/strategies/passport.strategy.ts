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
import {HashAlgorithmType} from "../types/hashAlgorithm.type";



/**
 *
 */
export class PassportStrategy {
    private errorCode: number = constants.HTTP_STATUS_BAD_REQUEST;
    private readonly publicRSAKeyPair: string;

    constructor(publicRSAKey: string) {
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
                                   algorithmHash: HashAlgorithmType, iteration: number, keyLength: number,
                                   encode: BufferEncoding | undefined): Promise<boolean> {
        const hashingService: HashPasswordService = new HashPasswordService();
        return await hashingService.verifyHashPassword(
            hashedPassword,
            salt,
            plainPassword,
            algorithmHash,
            iteration,
            keyLength,
            encode
        );
    }

    /**
     *
     * @param err
     * @param actionTitle
     * @param done
     */
    protected catchError = (err: any, actionTitle: any, done: (error: any, user?: any, info?: any) => void): void => {
        log.errorSpecified(msg.passportError, actionTitle, err.name, err.code, "Error", err.message, this.errorCode);
        done(null, false, { message: err.message });
    }



    /**
     * 
     * @param fetchUserByEmail 
     * @param email
     * @param done
     *
     */
    public validateLocalStrategyByEmail = async(fetchUserByEmail: (email: string) => Promise<any>,
                                                email: string,
                                                done: (error: any, user?: any, info?: any) => void): Promise<any> => {
        await fetchUserByEmail(email).then(async(user: any): Promise<any> => {
            if (!user) {
                log.error(msg.passportError, msg.localStrategyUserNotFound, msg.userNotFound, constants.HTTP_STATUS_NOT_FOUND);
                return done(null, false, { message: msg.userNotFound });
            }

            return done(null, user);
        }).catch((err: any): void => {
            this.catchError(err, msg.localStrategyUserNotFound, done);
        });
    }


    /**
     *
     * @param fetchUserByUsername
     * @param username
     * @param done
     *
     */
    public validateLocalStrategyByUsername = async (fetchUserByUsername: (username: string) => Promise<any>,
                                                    username: string,
                                                    done: (error: any, user?: any, info?: any) => void) => {
        return await fetchUserByUsername(username).then(async(item: any): Promise<any> => {
            if (!item) {
                log.error(msg.passportError, msg.localStrategyUserNotFound, msg.userNotFound, constants.HTTP_STATUS_NOT_FOUND);
                return done(null, false, { message: msg.userNotFound });
            }

            return done(null, item);
        }).catch((err: any): void => {
            this.catchError(err, msg.localStrategyUserNotFound, done);
        });
    }



    /**
     *
     * @param fetchIUserById
     * @param payload
     * @param done
     */
    public validateJwtStrategy = async(fetchIUserById: (userId: string) => Promise<any>,
                                       payload: JwtPayload,
                                       done: (error: any, user?: any, info?: any) => void): Promise<any> => {
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

            return done(null, user);
        } catch (err: any) {
            this.catchError(err, msg.jwtStrategyUserNotFound, done);
        }
    }


    /**
     * 
     * @param fetchUserByEmail 
     * @param email 
     * @param done
     * @param plainPassword
     * @returns 
     */
    public useLocalStrategyByEmail = async(fetchUserByEmail: (email: string) => Promise<any>, email: string, done: (error: any, user?: any, info?: any) => void, plainPassword: any)=> {
        PassportLocalStrategyUse<LocalStrategy, Object, VerifyLocalStrategyInterface>(
            "local",
            LocalStrategy,
            { email: email, password: plainPassword },
            await this.validateLocalStrategyByEmail(
                fetchUserByEmail,
                email,
                done,
            )
        );
    }


    /**
     *
     * @param fetchUserByUsername
     * @param username
     * @param done
     * @param plainPassword
     *
     */
    public useLocalStrategyByUsername = async(fetchUserByUsername: (username: string) => Promise<any>, username: string, done: (error: any, user?: any, info?: any) => void, plainPassword: any)=> {
        PassportLocalStrategyUse<LocalStrategy, Object, VerifyLocalStrategyInterface>(
            "local",
            LocalStrategy,
            { username: username, password: plainPassword },
            await this.validateLocalStrategyByUsername(
                fetchUserByUsername,
                username,
                done
            )
        );
    }


    /**
     * 
     * @param fetchIUserById
     * @returns 
     */
    public useJwtStrategy(fetchIUserById: (userId: string) => Promise<any>) {
        return PassportJWTStrategyUse<
            JwtStr,
            StrategyOptionsWithSecret,
            (payload: JwtPayload, done: (error: any, user?: any, info?: any) => void) => Promise<JwtPayload>
        >(
            "jwt",
            JwtStr,
            {
                jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
                secretOrKey: this.publicRSAKeyPair,
            },
            async (payload: JwtPayload, done: (error: any, user?: any, info?: any) => void) : Promise<any> => {
                await this.validateJwtStrategy(fetchIUserById, payload, done,)
            }
        );
    }
}