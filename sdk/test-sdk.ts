import { VaultAuthClient, VaultAuthError } from './src'

async function main() {
  const client = new VaultAuthClient({
    baseUrl: 'http://localhost:3000',
  })

  console.log('Testing VaultAuth SDK...\n')

  // Test register
  try {
    const result = await client.register(
      'sdk-test@example.com',
      'password123'
    )
    console.log('✅ Register:', result.message)
  } catch (err) {
    if (err instanceof VaultAuthError && err.code === 'EMAIL_ALREADY_EXISTS') {
      console.log('ℹ️  User already exists — skipping register')
    } else {
      console.error('❌ Register failed:', err)
    }
  }

  // Test login — need verified user
  try {
    const result = await client.login('sdk-test@example.com', 'password123')
    console.log('✅ Login:', result.user.email)
    console.log('   Roles:', result.user.roles)

    // Test getMe
    const me = await client.getMe()
    console.log('✅ GetMe:', me.email)

    // Test logout
    await client.logout()
    console.log('✅ Logout: success')

    // Test getMe after logout — should fail
    try {
      await client.getMe()
    } catch (err) {
      if (err instanceof VaultAuthError) {
        console.log('✅ GetMe after logout correctly failed:', err.code)
      }
    }
  } catch (err) {
    if (err instanceof VaultAuthError) {
      console.error('❌ Login failed:', err.code, err.message)
    }
  }

  console.log('\nSDK test complete.')
}

void main()