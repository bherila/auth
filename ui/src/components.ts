import type { AuthButtonComponent, AuthComponentOverrides, AuthComponentSet } from './types';

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

export function resolveAuthComponents(components?: AuthComponentOverrides): AuthComponentSet {
  const missing = requiredComponentKeys.filter((key) => !components?.[key]);

  if (missing.length > 0) {
    throw new Error(`bwh-auth requires injected components: ${missing.join(', ')}`);
  }

  return components as AuthComponentSet;
}

export function resolveAuthButtonComponent(components?: { Button?: AuthButtonComponent }): Pick<AuthComponentSet, 'Button'> {
  if (!components?.Button) {
    throw new Error('bwh-auth requires an injected Button component');
  }

  return { Button: components.Button };
}
