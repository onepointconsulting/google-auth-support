const fs = require('fs').promises
const { authenticate } = require('@google-cloud/local-auth')
const { google } = require('googleapis')

let initialScopes = [
  'https://www.googleapis.com/auth/admin.directory.group.member.readonly',
  'https://www.googleapis.com/auth/admin.directory.group.readonly',
]
if(!!process.env.GOOGLE_SCOPES) {
  // Override the scopes
  initialScopes = process.env.GOOGLE_SCOPES.split(',').map(s => s.trim())
}
const SCOPES = [...initialScopes]
const CREDENTIALS_PATH = process.env.GOOGLE_CREDENTIALS_PATH ||
  './client_secret_165820051388-0058a80cn1kgh4uk0ediif68t9m9n2ou.apps.googleusercontent.com.json'
const TOKEN_PATH = process.env.TOKEN_PATH || 'token.json'

/**
 * Reads previously authorized credentials from the save file.
 *
 * @param tokenPath The path where the Google Auth token is stored.
 *
 * @return {Promise<OAuth2Client|null>}
 */
async function loadSavedCredentialsIfExist (tokenPath = TOKEN_PATH) {
  try {
    const content = await fs.readFile(tokenPath)
    const credentials = JSON.parse(content)
    return google.auth.fromJSON(credentials)
  } catch (err) {
    return null
  }
}

/**
 * Serializes credentials to a file compatible with GoogleAUth.fromJSON.
 *
 * @param tokenPath The path where the Google Auth token is written to.
 * @param credentialsPath The path where the Google Auth secret json is stored.
 *
 * @param {OAuth2Client} client
 * @return {Promise<void>}
 */
async function saveCredentials (client, tokenPath = TOKEN_PATH, credentialsPath = CREDENTIALS_PATH) {
  const content = await fs.readFile(credentialsPath)
  const keys = JSON.parse(content)
  const key = keys.installed || keys.web
  const payload = JSON.stringify({
    type: 'authorized_user',
    client_id: key.client_id,
    client_secret: key.client_secret,
    refresh_token: client.credentials.refresh_token,
  })
  await fs.writeFile(tokenPath, payload)
}

/**
 * Load or request or authorization to call APIs.
 *
 * @param tokenPath The path where the Google Auth token is stored.
 * @param credentialsPath The path where the Google Auth secret json is stored.
 */
async function authorize (tokenPath = TOKEN_PATH, credentialsPath = CREDENTIALS_PATH) {
  let client = await loadSavedCredentialsIfExist(tokenPath)
  if (client) {
    return client
  }
  client = await authenticate({
    scopes: SCOPES,
    keyfilePath: credentialsPath,
  })
  if (client.credentials) {
    await saveCredentials(client, tokenPath, credentialsPath)
  }
  return client
}

module.exports = {
  authorize
}