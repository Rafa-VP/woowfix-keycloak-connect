import { NextFunction, Request, Response } from 'express';
import { KeycloakOptions, KeycloakConfig } from 'keycloak-connect';
type WKauth = {
    grant: WGrant;
};
type WGrant = {
    accessToken: string;
};
declare global {
    namespace Express {
        interface Request {
            kauth: WKauth | {};
        }
    }
}
export default class WoowfixKeycloakConnect {
    private KcClient;
    constructor(options?: KeycloakOptions | undefined, config?: string | KeycloakConfig | undefined);
    middleware: (req: Request, res: Response, next: NextFunction) => void;
    protect: (clientName: string, role?: string | string[]) => (req: Request, res: Response, next: NextFunction) => Response<any, Record<string, any>> | undefined;
}
export {};
