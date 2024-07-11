import {MessageUtils as msg} from "../utils/message.utils";

export class Passport {

    public async validateLocalStrategy(fetchUserByEmail: (email: string) => Promise<any>, email: string, password: string, done: any) {
        await fetchUserByEmail(email).then((user: any) => {
            if (!user) {

                return done(null, false, { message: msg.errorMessageUser });
            }
        }).catch((err: any) => {

        })
    }
}