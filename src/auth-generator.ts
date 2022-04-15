import { camel } from 'case';
import { format } from 'prettier';
import type {
  Generator,
  Method,
  OAuth2Scheme,
  OAuth2Scope,
  Parameter,
  Property,
  ValidationRule,
} from 'basketry';
import { warning } from './warning';

export type GuardClauseFactory = (
  param: Parameter | Property,
  rule: ValidationRule,
) => string | undefined;

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

  yield `export function ${camel(
    `authorize_${method.name}`,
  )}(${context}?: AuthService): AuthResponse {`;

  if (!method.security.length) {
    yield `  return 'authorized';`;
  } else {
    yield `  if(!${context}) return 'unauthenticated';`;
    for (const requirements of method.security) {
      const authConditions = requirements.map(
        (requirement) => `!${context}.isAuthenticated('${requirement.name}')`,
      );

      yield `  if(${authConditions.join(
        ' || ',
      )}) { return 'unauthenticated'; }`;

      const scopeConditions = requirements
        .filter((scheme): scheme is OAuth2Scheme => scheme.type === 'oauth2')
        .map<[OAuth2Scheme, OAuth2Scope[]]>((scheme) => [
          scheme,
          scheme.flows.map((f) => f.scopes).reduce((a, b) => a.concat(b), []),
        ])
        .reduce<[OAuth2Scheme, OAuth2Scope][]>(
          (acc, [scheme, scopes]) =>
            acc.concat(
              scopes.map<[OAuth2Scheme, OAuth2Scope]>((scope) => [
                scheme,
                scope,
              ]),
            ),
          [],
        )
        .map(
          ([scheme, scope]) =>
            `!${context}.hasScope('${scheme.name}', '${scope.name}')`,
        );

      if (scopeConditions.length) {
        yield `  if(${scopeConditions.join(' || ')}) { return 'unauthorized' }`;
      }
    }
    yield `  return 'authorized';`;
  }

  yield `}`;
}
