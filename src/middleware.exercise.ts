import {cookies} from 'next/headers'
import {NextResponse, type NextRequest} from 'next/server'
import {decrypt} from './app/exercises/auth/lib/crypt'
import {RoleEnum} from './lib/type'

const protectedRoutes = new Set([
  '/exercises/dashboard',
  '/exercises/bank-account',
])
const publicRoutes = new Set(['/'])

// 🐶 Spécifie les routes 'admin'
// 'isAdminRoute' est un Set qui contient les routes admin
const adminRoute = new Set(['/admin'])
// 🐶 Spécifie les routes 'redactor'
// 'redactorRoute' est un Set qui contient les routes redactor
const redactorRoute = new Set(['/redaction'])

export async function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname
  const isProtectedRoute = protectedRoutes.has(path)
  const isPublicRoute = publicRoutes.has(path)

  // 🐶 Vérifie si la route est une route admin
  // 🤖 isAdminRoute
  const isAdminRoute = adminRoute.has(path)
  // 🐶 Vérifie si la route est une route redactor
  const isRedactorRoute = redactorRoute.has(path)
  const cookieStore = await cookies()
  const cookie = cookieStore.get('session')?.value
  const session = await decrypt(cookie)
  console.log(session)
  const role = session?.role

  const hasSession = session?.userId || session?.sessionId

  if (isProtectedRoute && !hasSession) {
    return NextResponse.redirect(new URL('/exercises/login', request.nextUrl))
  }

  // 🐶 Redirige l'utilisateur si la route est une route admin
  // Redirige vers '/restricted/' si l'utilisateur n'est pas admin
  console.log('Roles: ', role)
  if (
    isAdminRoute &&
    ![RoleEnum.ADMIN, RoleEnum.SUPER_ADMIN].includes(role as RoleEnum)
  ) {
    return NextResponse.redirect(new URL('/resctricted', request.nextUrl))
  }
  // 🐶 Redirige l'utilisateur si la route est une route redactor
  // Redirige vers '/restricted/' si l'utilisateur n'est pas redactor ou admin
  if (
    isRedactorRoute &&
    ![RoleEnum.ADMIN, RoleEnum.SUPER_ADMIN, RoleEnum.REDACTOR].includes(
      role as RoleEnum
    )
  ) {
    return NextResponse.redirect(new URL('/resctricted', request.nextUrl))
  }

  if (isPublicRoute && hasSession) {
    return NextResponse.redirect(new URL('/exercises/auth', request.nextUrl))
  }
  NextResponse.next()
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|.*\\.png$).*)'],
}
