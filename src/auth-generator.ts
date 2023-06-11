import {
  Generator,
  isOAuth2Scheme,
  Method,
  NamespacedBasketryOptions,
  Service,
  warning as standardWarning,
} from 'basketry';
import { format } from 'prettier';

import { buildMethodAuthorizerName } from './name-factory';

function* warning(
  service: Service,
  options: NamespacedBasketryOptions,
): Iterable<string> {
  yield '/*';
  yield* standardWarning(service, require('../package.json'), options || {});
  yield '*/';
}

export const generateAuth: Generator = (service, options) => {
  const methods: Method[] = service.interfaces
    .map((int) => int.methods)
    .reduce((a, b) => a.concat(b), []);

  const standardTypes = Array.from(buildStandardTypes()).join('\n');

  const authorizers = methods
    .map((method) => Array.from(buildMethodAuthorizer(method)).join('\n'))
    .join('\n\n');

  const contents = [
    Array.from(warning(service, options)).join('\n'),
    standardTypes,
    authorizers,
  ].join('\n\n');
  const formatted = format(contents, {
    singleQuote: true,
    useTabs: false,
    tabWidth: 2,
    trailingComma: 'all',
    parser: 'typescript',
  });

  return [
    {
      path: [`v${service.majorVersion.value}`, 'auth.ts'],
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

    const hasScopes = method.security.flatMap((x) => x).some(isOAuth2Scheme);

    if (hasScopes) {
      yield `let authenticated = false;`;
    }

    for (const securityOption of method.security) {
      const authZConditions: string[] = [];
      const authNConditions: string[] = [];

      securityOption.forEach((scheme) => {
        const authNCondition = `${context}.isAuthenticated('${scheme.name.value}')`;
        authNConditions.push(authNCondition);

        if (isOAuth2Scheme(scheme)) {
          for (const scope of scheme.flows.flatMap((flow) => flow.scopes)) {
            authZConditions.push(
              `${context}.hasScope('${scheme.name.value}', '${scope.name.value}')`,
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
