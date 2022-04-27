import { Method } from 'basketry';
import { camel } from 'case';

function prefix(authModule: string | undefined, name: string) {
  return authModule ? `${authModule}.${name}` : name;
}

export function buildMethodAuthorizerName(
  method: Method,
  authModule?: string,
): string {
  return prefix(authModule, camel(`authorize_${method.name.value}`));
}
