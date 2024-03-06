# Authentication Libraries Configuration

## Unix

- `passwordFile`: Path to the password file.
- `groupFile`: Path to the group file.
- `configDirectory`: Alternative directory for configuration.

## Apache htpassword

- `passwordFile`: Path to the password file (if present).
- `groupFile`: Path to the group file (optional).
- `configDirectory`: Alternative directory for configuration.

## LDAP

- `passwordKeyName`: Key name for the password.
- `searchBase`: Base search path.
- `groupSearchBase`: Search base for groups.
- Other Key-Value Pairs: Various other configurations as required.

## AWS-Cognito

- `userPoolId`: Identifier for the user pool.
- `appClientId`: Application client identifier.
- `appClientSecret`: Application client secret.
- `region`: AWS region name.
- `accessKeyId`: AWS access key identifier.
- `secretAccessKey`: AWS secret access key.
- `cacheTime`: Duration for caching.

## Auth0

- `domain`: Auth0 domain.
- `clientId`: Client identifier.
- `clientSecret`: Client secret.
- `authToken`: Authentication token.
- `cacheTime`: Duration for caching.
