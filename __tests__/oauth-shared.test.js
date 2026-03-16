import { parseScope } from '../lib/oauth/shared.js';

describe('oauth shared', () => {
  test('parseScope defaults to profile', () => {
    expect(parseScope(null)).toEqual(['profile']);
    expect(parseScope('')).toEqual(['profile']);
  });

  test('parseScope intersects requested with allowed scopes', () => {
    expect(parseScope('profile email openid', ['profile'])).toEqual(['profile']);
    expect(parseScope('email openid', ['email', 'openid'])).toEqual(['email', 'openid']);
  });

  test('parseScope ignores unknown scopes', () => {
    expect(parseScope('profile admin', ['profile', 'email'])).toEqual(['profile']);
  });
});

