/*
This code was generated by @basketry/typescript-auth@{{version}}

Changes to this file may cause incorrect behavior and will be lost if
the code is regenerated.

To make changes to the contents of this file:
1. Edit source/path.ext
2. Run the Basketry CLI

About Basketry: https://github.com/basketry/basketry/wiki
About @basketry/typescript-auth: https://github.com/basketry/typescript-auth#readme
*/

export interface AuthService {
  isAuthenticated(scheme: string): boolean;
  hasScope(scheme: string, scope: string): boolean;
}
export type AuthResponse = 'authorized' | 'unauthenticated' | 'unauthorized';

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

export function authorizeExhaustiveFormats(
  _context?: AuthService,
): AuthResponse {
  return 'authorized';
}

export function authorizeExhaustiveParams(
  _context?: AuthService,
): AuthResponse {
  return 'authorized';
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

export function authorizeUploadGizmo(_context?: AuthService): AuthResponse {
  return 'authorized';
}

export function authorizeCreateWidget(context?: AuthService): AuthResponse {
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

export function authorizeGetWidgetFoo(context?: AuthService): AuthResponse {
  if (!context) return 'unauthenticated';
  if (context.isAuthenticated('apiKeyAuth')) {
    return 'authorized';
  }
  return 'unauthenticated';
}

export function authorizeGetWidgets(context?: AuthService): AuthResponse {
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
