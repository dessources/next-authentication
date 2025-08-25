//3. 🚀 Session segmentée par user agent
import {cookies, headers} from 'next/headers'
import {randomUUID} from 'node:crypto'
import {
  addSession as addSessionDao,
  findSession as findSessionDao,
  deleteSession as deleteSessionDao,
  updateSession as updateSessionDao,
  findSessionByUidUserAgent,
  getUserById,
} from '@/db/sgbd'
import {decrypt, encrypt, EXPIRE_TIME, isExpired} from './crypt'

//3. 🚀 Session segmentée par user agent
export async function createSession(uid: string) {
  const headersList = await headers()
  const userAgent = headersList.get('User-Agent')
  console.log('createSession userAgent', userAgent)

  const expiresAt = new Date(Date.now() + EXPIRE_TIME)

  //1 . Récupération session par `uid` et `userAgent`
  const sessionByUid = await findSessionByUidUserAgent(uid, userAgent ?? '')

  // SESSION EXISTE ET NON EXPIRE
  if (sessionByUid && !isExpired(sessionByUid.expiresAt)) {
    // 1. Update the session in the database
    sessionByUid.expiresAt = expiresAt.toISOString()
    await updateSessionDao(sessionByUid)

    // 2. Encrypt the session ID for cookie
    const session = await encrypt({
      sessionId: sessionByUid.sessionId,
      expiresAt,
    })
    const cookieStore = await cookies()
    cookieStore.set('session', session, {
      httpOnly: true,
      secure: true,
      expires: expiresAt,
      sameSite: 'lax',
      path: '/',
    })
    return
  }
  // NOUVELLE SESSION (ancien algo)
  // 1. Create a session in the database
  const sessionId = randomUUID()

  await addSessionDao({
    sessionId,
    userId: uid,
    expiresAt: expiresAt.toISOString(),
    userAgent,
  })
  const user = await getUserById(uid)
  console.log('user: ', uid, 'role: ', user?.role)
  // 2. Encrypt the session ID
  const session = await encrypt({sessionId, expiresAt, role: user?.role})

  // 3. Store the session in cookies for optimistic auth checks
  const cookieStore = await cookies()
  cookieStore.set('session', session, {
    httpOnly: true,
    secure: true,
    expires: expiresAt,
    sameSite: 'lax',
    path: '/',
  })
}

export async function verifySession() {
  const cookieStore = await cookies()
  const cookie = cookieStore.get('session')?.value
  const session = await decrypt(cookie)
  console.log('verifySession cookie', cookie, session)

  if (!session || !session.sessionId) {
    console.log('verifySession No session found')
    return
  }
  //GET DB SESSION
  const sessionDao = await findSessionDao(session.sessionId)
  if (sessionDao && !isExpired(sessionDao?.expiresAt)) {
    return {
      isAuth: true,
      userId: sessionDao.userId,
      sessionId: session.sessionId,
    }
  }
  console.log('verifySession Session (database) expired')

  return {
    isAuth: false,
  }
}

export async function deleteSession() {
  const cookieStore = await cookies()
  const cookie = cookieStore.get('session')?.value
  const session = await decrypt(cookie)
  if (session) {
    deleteSessionDao(session.sessionId ?? '')
  }
  cookieStore.delete('session')
}

//1. 🚀 Update Session
export async function updateSession() {
  // disable
  // const session = cookies().get('session')?.value
  // const payload = await decrypt(session)
  // if (!session || !payload) {
  //   return
  // }
  // //UPDATE DB SESSION
  // const expires = new Date(Date.now() + EXPIRE_TIME)
  // const sessionDb = await findSessionDao(payload.sessionId as string)
  // if (sessionDb) {
  //   sessionDb.expiresAt = expires.toISOString()
  //   await updateSessionDao(sessionDb)
  // }
  // Cookies can only be modified in a Server Action or Route Handler
  // cookies().set('session', session, {
  //   httpOnly: true,
  //   secure: true,
  //   expires,
  //   sameSite: 'lax',
  //   path: '/',
  // })
}
