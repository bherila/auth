import type { AuthButtonComponentInput, AuthComponentInput, AuthComponentSet } from './types';

const requiredComponentKeys: Array<keyof AuthComponentSet> = [
  'Button',
  'Card',
  'CardContent',
  'CardDescription',
  'CardHeader',
  'CardTitle',
  'Input',
  'Label',
];

export function resolveAuthComponents(components?: AuthComponentInput): AuthComponentSet {
  const missing = requiredComponentKeys.filter((key) => !components?.[key]);

  if (missing.length > 0) {
    throw new Error(`bwh-auth requires injected components: ${missing.join(', ')}`);
  }

  return components as AuthComponentSet;
}

export function resolveAuthButtonComponent(components?: AuthButtonComponentInput): Pick<AuthComponentSet, 'Button'> {
  if (!components?.Button) {
    throw new Error('bwh-auth requires an injected Button component');
  }

  return { Button: components.Button };
}
