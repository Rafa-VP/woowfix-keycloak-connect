"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const keycloak_connect_1 = __importDefault(require("keycloak-connect"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const http_status_codes_1 = require("http-status-codes");
class WoowfixKeycloakConnect {
    constructor(options, config) {
        this.middleware = (req, res, next) => {
            req.kauth = {};
            next();
        };
        this.protect = (clientName, role) => {
            return (req, res, next) => {
                var _a, _b;
                const token = (_b = (_a = req.headers) === null || _a === void 0 ? void 0 : _a.authorization) === null || _b === void 0 ? void 0 : _b.split(' ')[1];
                try {
                    if (req.headers.authorization) {
                        this.KcClient.grantManager
                            .validateAccessToken(token)
                            .then((result) => {
                            var _a, _b, _c, _d;
                            if (result === false) {
                                return res
                                    .status(http_status_codes_1.StatusCodes.UNAUTHORIZED)
                                    .json({
                                    message: 'Secret Token Invalid',
                                    authendication: 'Unauthorized'
                                });
                            }
                            else {
                                req.kauth = {
                                    grant: { accessToken: result }
                                };
                                const decoded = jsonwebtoken_1.default.decode(result);
                                if (typeof role === 'string') {
                                    // @ts-ignore
                                    const roles = (_b = (_a = decoded === null || decoded === void 0 ? void 0 : decoded.resource_access) === null || _a === void 0 ? void 0 : _a[clientName]) === null || _b === void 0 ? void 0 : _b.roles; // Array of string with roles;
                                    if (roles.includes(role)) {
                                        next();
                                        return;
                                    }
                                    return res
                                        .status(http_status_codes_1.StatusCodes.UNAUTHORIZED)
                                        .json({
                                        error: 'Insufficient permissions'
                                    });
                                }
                                if (typeof role === 'object') {
                                    // @ts-ignore
                                    const roles = (_d = (_c = decoded === null || decoded === void 0 ? void 0 : decoded.resource_access) === null || _c === void 0 ? void 0 : _c[clientName]) === null || _d === void 0 ? void 0 : _d.roles; // Array of string with roles;
                                    if (role.every((_role) => roles.includes(_role))) {
                                        next();
                                        return;
                                    }
                                    return res
                                        .status(http_status_codes_1.StatusCodes.UNAUTHORIZED)
                                        .json({
                                        error: 'Insufficient permissions'
                                    });
                                }
                                next();
                                return;
                            }
                        })
                            .catch((err) => {
                            return res.status(http_status_codes_1.StatusCodes.UNAUTHORIZED).json({
                                error: 'Invalid token',
                                details: err
                            });
                        });
                    }
                    else {
                        return res.status(http_status_codes_1.StatusCodes.UNAUTHORIZED).json({
                            message: 'Token is required',
                            authendication: 'Authorization header is required'
                        });
                    }
                }
                catch (err) {
                    return res.status(http_status_codes_1.StatusCodes.INTERNAL_SERVER_ERROR).send(err);
                }
            };
        };
        this.KcClient = new keycloak_connect_1.default(options, config);
    }
}
exports.default = WoowfixKeycloakConnect;
