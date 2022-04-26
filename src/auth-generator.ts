import type { Generator, Method } from 'basketry';
import { format } from 'prettier';

import { buildMethodAuthorizerName } from './name-factory';
import { warning } from './warning';

export const generateAuth: Generator = (service) => {
  const methods: Method[] = service.interfaces
    .map((int) => int.methods)
    .reduce((a, b) => a.concat(b), []);

  const standardTypes = Array.from(buildStandardTypes()).join('\n');

  const authorizers = methods
    .map((method) => Array.from(buildMethodAuthorizer(method)).join('\n'))
    .join('\n\n');

  const contents = [warning, standardTypes, authorizers].join('\n\n');
  const formatted = format(contents, {
    singleQuote: true,
    useTabs: false,
    tabWidth: 2,
    trailingComma: 'all',
    parser: 'typescript',
  });

  return [
    {
      path: [`v${service.majorVersion}`, 'auth.ts'],
      contents: formatted,
    },
  ];
};

function* buildStandardTypes(): Iterable<string> {
  yield 'export interface AuthService { isAuthenticated(scheme: string): boolean; hasScope(scheme: string, scope: string): boolean; }';
  yield `export type AuthResponse = 'authorized' | 'unauthenticated' | 'unauthorized';`;
}

function* buildMethodAuthorizer(method: Method): Iterable<string> {
  const context = method.security.length ? 'context' : '_context';

  yield `export function ${buildMethodAuthorizerName(
    method,
  )}(${context}?: AuthService): AuthResponse {`;

  if (!method.security.length) {
    yield `  return 'authorized';`;
  } else {
    yield `  if(!${context}) return 'unauthenticated';`;

    const hasScopes = method.security
      .flatMap((x) => x)
      .some((x) => x.type === 'oauth2');

    if (hasScopes) {
      yield `let authenticated = false;`;
    }

    for (const securityOption of method.security) {
      const authZConditions: string[] = [];
      const authNConditions: string[] = [];

      securityOption.forEach((scheme) => {
        const authNCondition = `${context}.isAuthenticated('${scheme.name}')`;
        authNConditions.push(authNCondition);

        if (scheme.type === 'oauth2') {
          for (const scope of scheme.flows.flatMap((flow) => flow.scopes)) {
            authZConditions.push(
              `${context}.hasScope('${scheme.name}', '${scope.name}')`,
            );
          }
        }
      });

      if (authNConditions.length) {
        yield `  if(${authNConditions.join(' && ')}) {`;

        if (authZConditions.length) {
          yield `  authenticated = true;`;

          yield `  if(${authZConditions.join(' && ')}) {`;
          yield `  return 'authorized';`;
          yield ` }`;
        } else {
          yield `  return 'authorized';`;
        }

        yield ` }`;
      }
    }
    if (hasScopes) {
      yield `  return authenticated ? 'unauthorized' : 'unauthenticated';`;
    } else {
      yield `  return 'unauthenticated';`;
    }
  }

  yield `}`;
}
