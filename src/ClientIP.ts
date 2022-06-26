/* eslint-disable max-classes-per-file */

import * as http from "http";
import * as net from "net";
import type * as ProxyAddrType from "proxy-addr";

let ProxyAddr: typeof ProxyAddrType;
try {
    ProxyAddr = require("proxy-addr");
}
catch (_) {
}

export interface RequestLike {
    headers: http.IncomingHttpHeaders;
    connection?: {
        remoteAddress?: string | undefined;
        socket?: {
            remoteAddress?: string | undefined
        } | undefined;
    } | undefined;
    info?: {
        remoteAddress?: string | undefined
    } | undefined;
    socket?: {
        remoteAddress?: string | undefined
    } | undefined;
    requestContext?: {
        identity?: {
            sourceIp?: string;
        };
    };
}

export type HeaderConfig = string|[string, HeaderValidatorConfig];
export type HeaderValidatorConfig = {[key: string]: unknown};
export type HeaderValidator = (headerValue: string, headerConfig: HeaderValidatorConfig) => string|null;
export type HeaderValidators = {[headerName: string]: HeaderValidator};
export type RemoteAddressValidator = string|string[]|((ip: string) => boolean);

export interface Configuration {
    allowedRemotes?: RemoteAddressValidator;
    allowedHeaders?: HeaderConfig[];
    headerValidators?: HeaderValidators;
}

export class ClientIPValidator {
    
    static readonly INSTANCE = new ClientIPValidator([
        "x-client-ip",
        "x-forwarded-for",
        "cf-connecting-ip",
        "fastly-client-ip",
        "true-client-ip",
        "x-real-ip",
        "x-cluster-client-ip",
        "x-forwarded",
        "forwarded-for",
        "forwarded"
    ], {
        "forwarded-for": getClientIpFromXForwardedFor,
        forwarded: getClientIpFromForwarded
    });
    
    constructor(
        public allowedHeaders: HeaderConfig[],
        public headerValidators: HeaderValidators
    ) {
    }
    
    getClientIp(request: RequestLike, config?: Configuration): string|null {
        const theConfig = config || {};
        if (theConfig.allowedRemotes) {
            const remoteAddress = this.getRemoteAddress(request);
            if (!remoteAddress || !validateRemoteAddress(remoteAddress, theConfig.allowedRemotes)) {
                return remoteAddress;
            }
        }
        const allowedHeaders = theConfig.allowedHeaders || this.allowedHeaders;
        for (const headerConfig of allowedHeaders) {
            const ip = this.tryExtractIpUsingConfig(request, headerConfig, theConfig.headerValidators);
            if (ip) {
                return ip;
            }
        }
        return this.getRemoteAddress(request);
    }
    
    tryExtractIpUsingConfig(request: RequestLike, config: HeaderConfig, headerValidators?: HeaderValidators): string|null {
        const [headerName, headerConfig] = typeof(config) === "string" ? [config, {}] : config;
        const headerRawValue = request.headers[headerName];
        if (!headerRawValue) {
            return null;
        }
        const headerValue = typeof(headerRawValue) == "string" ? headerRawValue : headerRawValue[0];
        const validator = (headerValidators ? headerValidators[headerName] : null) || this.headerValidators[headerName];
        if (validator) {
            return validator(headerValue, headerConfig);
        }
        return net.isIP(headerValue) ? headerValue : null;
    }
    
    getRemoteAddress(request: RequestLike): string|null {
        // Remote address checks.
        if (request.connection) {
            if (request.connection.remoteAddress && net.isIP(request.connection.remoteAddress)) {
                return request.connection.remoteAddress;
            }
            if (request.connection.socket && request.connection.socket.remoteAddress && net.isIP(request.connection.socket.remoteAddress)) {
                return request.connection.socket.remoteAddress;
            }
        }
        
        if (request.socket && request.socket.remoteAddress && net.isIP(request.socket.remoteAddress)) {
            return request.socket.remoteAddress;
        }
        
        if (request.info && request.info.remoteAddress && net.isIP(request.info.remoteAddress)) {
            return request.info.remoteAddress;
        }
        
        // AWS Api Gateway + Lambda
        if (request.requestContext && request.requestContext.identity && request.requestContext.identity.sourceIp && net.isIP(request.requestContext.identity.sourceIp)) {
            return request.requestContext.identity.sourceIp;
        }
        
        return null;
    }
}

export function validateRemoteAddress(ip: string, validator: RemoteAddressValidator) {
    if (typeof(validator) == "function") {
        return validator(ip);
    }
    if (ProxyAddr) {
        const func = ProxyAddr.compile(validator);
        return func(ip, 0);
    }
    const list = typeof(validator) == "string" ? validator.split(",").map(x => x.trim()) : validator;
    return list.includes(ip);
}

export function getClientIpFromXForwardedFor(headerValue: string): string|null {
    const segment = headerValue.split(",")[0];
    return extractIP(segment.trim());
}

export function getClientIpFromForwarded(headerValue: string, headerConfig?: HeaderValidatorConfig): string|null {
    const segment = headerValue.split(",")[0];
    const entries = segment.split(";").map(part => {
        const splitted = part.trim().split("=");
        if (splitted.length != 2) {
            return null;
        }
        let value = splitted[1].trim();
        if (value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length - 1);
        }
        return splitted.length == 2 && splitted[0] ? {key: splitted[0].trim().toLowerCase(), value: value} : null;
    }).filter(x => !!x) as {key: string, value: string}[];
    // validate forwarded header
    if (headerConfig) {
        for (const key in headerConfig) {
            const keyLowered = key.toLowerCase();
            const value = headerConfig[key];
            const entry = entries.find(x => x.key == keyLowered);
            if (!entry || entry.value != value) {
                return null;
            }
        }
    }
    const ipEntry = entries.find(x => x.key == "for");
    return ipEntry ? extractIP(ipEntry.value) : null;
}

export function extractIP(ip: string) {
    // check ipv6
    if (ip.startsWith("[")) {
        const index = ip.indexOf("]");
        if (index == -1) {
            return null;
        }
        ip = ip.substring(1, index);
    }
    // remove port from ipv4
    else if (ip.includes(":")) {
        const splitted = ip.split(":");
        // make sure we only use this if it's ipv4 (ip:port)
        if (splitted.length === 2) {
            ip = splitted[0];
        }
    }
    return net.isIP(ip) ? ip : null;
}

export class ClientIP {
    
    private validator: ClientIPValidator
    
    constructor(
        private config?: Configuration,
        validator?: ClientIPValidator
    ) {
        this.validator = validator || ClientIPValidator.INSTANCE;
    }
    
    getClientIP(request: RequestLike) {
        return this.validator.getClientIp(request, this.config);
    }
    
    static getClientIP(request: RequestLike, config?: Configuration) {
        return ClientIPValidator.INSTANCE.getClientIp(request, config);
    }
}

export type ExpressFunc = (req: RequestLike, _res: unknown, next: Function) => void;

export function expressMiddleware(clientId: ClientIP, config?: {attributeName?: string}): ExpressFunc;
export function expressMiddleware(config?: Configuration&{attributeName?: string}): ExpressFunc;
export function expressMiddleware(configOrClient?: ClientIP|Configuration&{attributeName?: string}, config?: {attributeName?: string}): ExpressFunc {
    // Defaults.
    const clientIP = configOrClient instanceof ClientIP ? configOrClient : new ClientIP(configOrClient);
    const configuration = (configOrClient instanceof ClientIP ? config : configOrClient) || {};
    
    const attributeName = configuration.attributeName || "ip";
    return (req: RequestLike, _res: unknown, next: Function) => {
        const ip = clientIP.getClientIP(req);
        Object.defineProperty(req, attributeName, {
            get: () => ip,
            configurable: true
        });
        next();
    };
}
