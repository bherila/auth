<?php

namespace BWH\Auth\OAuth\Introspection;

interface OAuthTokenIntrospector
{
    /**
     * @throws OAuthIntrospectionException when the authorization server is unavailable or misconfigured
     */
    public function introspect(string $token): IntrospectedToken;
}
