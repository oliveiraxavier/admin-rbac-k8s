import { HttpInterceptorFn } from '@angular/common/http';
import { catchError, throwError } from 'rxjs';

export const authInterceptor: HttpInterceptorFn = (request, next) =>
  next(request).pipe(
    catchError((error) => {
      if (error.status === 401 && !request.url.startsWith('/auth/')) {
        const returnUrl =
          window.location.pathname + window.location.search + window.location.hash;
        sessionStorage.setItem('kubeaccess_return_url', returnUrl);
        window.location.assign('/login');
      }
      return throwError(() => error);
    }),
  );
