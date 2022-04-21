/**
 * This code was generated by a tool.
 * @basketry/typescript-auth@{{version}}
 *
 * Changes to this file may cause incorrect behavior and will be lost if
 * the code is regenerated.
 */

export interface AuthService {
  isAuthenticated(scheme: string): boolean;
  hasScope(scheme: string, scope: string): boolean;
}
export type AuthResponse = 'authorized' | 'unauthenticated' | 'unauthorized';

export function authorizeGetGizmos(context?: AuthService): AuthResponse {
  if (!context) return 'unauthenticated';
  let authenticated = false;
  if (context.isAuthenticated('oauth2Auth')) {
    authenticated = true;
    if (context.hasScope('oauth2Auth', 'read:gizmos')) {
      return 'authorized';
    }
  }
  return authenticated ? 'unauthorized' : 'unauthenticated';
}

export function authorizeCreateGizmo(context?: AuthService): AuthResponse {
  if (!context) return 'unauthenticated';
  let authenticated = false;
  if (context.isAuthenticated('oauth2Auth')) {
    authenticated = true;
    if (context.hasScope('oauth2Auth', 'write:gizmos')) {
      return 'authorized';
    }
  }
  return authenticated ? 'unauthorized' : 'unauthenticated';
}

export function authorizeUpdateGizmo(context?: AuthService): AuthResponse {
  if (!context) return 'unauthenticated';
  let authenticated = false;
  if (context.isAuthenticated('oauth2Auth')) {
    authenticated = true;
    if (
      context.hasScope('oauth2Auth', 'write:gizmos') &&
      context.hasScope('oauth2Auth', 'admin:gizmos')
    ) {
      return 'authorized';
    }
  }
  return authenticated ? 'unauthorized' : 'unauthenticated';
}

export function authorizeGetWidgets(context?: AuthService): AuthResponse {
  if (!context) return 'unauthenticated';
  if (context.isAuthenticated('apiKeyAuth')) {
    return 'authorized';
  }
  return 'unauthenticated';
}

export function authorizeCreateWidget(context?: AuthService): AuthResponse {
  if (!context) return 'unauthenticated';
  if (context.isAuthenticated('apiKeyAuth')) {
    return 'authorized';
  }
  return 'unauthenticated';
}

export function authorizePutWidget(context?: AuthService): AuthResponse {
  if (!context) return 'unauthenticated';
  if (context.isAuthenticated('apiKeyAuth')) {
    return 'authorized';
  }
  return 'unauthenticated';
}

export function authorizeGetWidgetFoo(context?: AuthService): AuthResponse {
  if (!context) return 'unauthenticated';
  if (context.isAuthenticated('apiKeyAuth')) {
    return 'authorized';
  }
  return 'unauthenticated';
}

export function authorizeDeleteWidgetFoo(context?: AuthService): AuthResponse {
  if (!context) return 'unauthenticated';
  if (context.isAuthenticated('apiKeyAuth')) {
    return 'authorized';
  }
  return 'unauthenticated';
}

export function authorizeExhaustiveParams(
  _context?: AuthService,
): AuthResponse {
  return 'authorized';
}

export function authorizeAllAuthSchemes(context?: AuthService): AuthResponse {
  if (!context) return 'unauthenticated';
  let authenticated = false;
  if (context.isAuthenticated('basicAuth')) {
    return 'authorized';
  }
  if (context.isAuthenticated('alternate-basic-auth')) {
    return 'authorized';
  }
  if (context.isAuthenticated('apiKeyAuth')) {
    return 'authorized';
  }
  if (context.isAuthenticated('oauth2Auth')) {
    authenticated = true;
    if (context.hasScope('oauth2Auth', 'admin:gizmos')) {
      return 'authorized';
    }
  }
  return authenticated ? 'unauthorized' : 'unauthenticated';
}

export function authorizeComboAuthSchemes(context?: AuthService): AuthResponse {
  if (!context) return 'unauthenticated';
  let authenticated = false;
  if (
    context.isAuthenticated('basicAuth') &&
    context.isAuthenticated('apiKeyAuth')
  ) {
    return 'authorized';
  }
  if (
    context.isAuthenticated('basicAuth') &&
    context.isAuthenticated('alternateApiKeyAuth')
  ) {
    return 'authorized';
  }
  if (
    context.isAuthenticated('alternate-basic-auth') &&
    context.isAuthenticated('oauth2Auth')
  ) {
    authenticated = true;
    if (context.hasScope('oauth2Auth', 'admin:gizmos')) {
      return 'authorized';
    }
  }
  return authenticated ? 'unauthorized' : 'unauthenticated';
}
