import { NextFunction, Request, Response } from 'express';
import Keycloak from 'keycloak-connect';
export declare class WoowfixKeycloakConnect {
    private KcClient;
    constructor(
        options?: Keycloak.KeycloakOptions | undefined,
        config?: string | Keycloak.KeycloakConfig | undefined
    );
    middleware: (req: Request, res: Response, next: NextFunction) => void;
    protect: (
        clientName: string,
        role?: string | string[]
    ) => (
        req: Request,
        res: Response,
        next: NextFunction
    ) => Response<any, Record<string, any>> | undefined;
}

