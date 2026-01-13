<?php
/**
 * API Security Dojo Configuration
 */

namespace ApiSecurityDojo;

class Config
{
    // VULNERABILITY V02: Weak secret key
    public const JWT_SECRET = 'secret123';

    public static function getMode(): string
    {
        return getenv('DOJO_MODE') ?: 'challenge';
    }

    public static function getDbPath(): string
    {
        return __DIR__ . '/../vulnapi.db';
    }
}
