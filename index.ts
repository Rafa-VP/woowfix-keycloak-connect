import { NextFunction, Request, Response } from 'express';
import KeycloakConnect, {
    KeycloakOptions,
    KeycloakConfig,
    Keycloak
} from 'keycloak-connect';
import Jwt from 'jsonwebtoken';
import { StatusCodes } from 'http-status-codes';

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
    private KcClient: Keycloak;
    constructor(
        options?: KeycloakOptions | undefined,
        config?: string | KeycloakConfig | undefined
    ) {
        this.KcClient = new KeycloakConnect(options, config);
    }
    public middleware = (req: Request, res: Response, next: NextFunction) => {
        req.kauth = {};
        next();
    };
    public protect = (clientName: string, role?: string | string[]) => {
        return (req: Request, res: Response, next: NextFunction) => {
            const token = req.headers?.authorization?.split(' ')[1];
            try {
                if (req.headers.authorization) {
                    this.KcClient.grantManager
                        .validateAccessToken(token!)
                        .then((result) => {
                            if (result === false) {
                                return res
                                    .status(StatusCodes.UNAUTHORIZED)
                                    .json({
                                        message: 'Secret Token Invalid',
                                        authendication: 'Unauthorized'
                                    });
                            } else {
                                req.kauth = {
                                    grant: { accessToken: result }
                                };
                                const decoded = Jwt.decode(result);
                                if (typeof role === 'string') {
                                    // @ts-ignore
                                    const roles = decoded?.resource_access?.[
                                        clientName
                                    ]?.roles as string[]; // Array of string with roles;
                                    if (roles.includes(role)) {
                                        next();
                                        return;
                                    }
                                    return res
                                        .status(StatusCodes.UNAUTHORIZED)
                                        .json({
                                            error: 'Insufficient permissions'
                                        });
                                }
                                if (typeof role === 'object') {
                                    // @ts-ignore
                                    const roles = decoded?.resource_access?.[
                                        clientName
                                    ]?.roles as string[]; // Array of string with roles;
                                    if (
                                        role.every((_role) =>
                                            roles.includes(_role)
                                        )
                                    ) {
                                        next();
                                        return;
                                    }
                                    return res
                                        .status(StatusCodes.UNAUTHORIZED)
                                        .json({
                                            error: 'Insufficient permissions'
                                        });
                                }
                                next();
                                return;
                            }
                        })
                        .catch((err) => {
                            return res.status(StatusCodes.UNAUTHORIZED).json({
                                error: 'Invalid token',
                                details: err
                            });
                        });
                } else {
                    return res.status(StatusCodes.UNAUTHORIZED).json({
                        message: 'Token is required',
                        authendication: 'Authorization header is required'
                    });
                }
            } catch (err) {
                return res.status(StatusCodes.INTERNAL_SERVER_ERROR).send(err);
            }
        };
    };
}

