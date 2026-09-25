import Auth from '../api/auth';
import { isSsoMode } from 'shared/helpers/ssoMode';
import { recoverSession } from './ssoSession';

const RECOVERABLE_ERROR_CODES = [
  'sso_identity_changed',
  'sso_session_required',
];

const errorCodeOf = error => {
  const data = error?.response?.data;
  const isObject =
    data !== null && typeof data === 'object' && !Array.isArray(data);
  return isObject && typeof data.error_code === 'string'
    ? data.error_code
    : null;
};

const parseErrorCode = error => {
  if (isSsoMode() && RECOVERABLE_ERROR_CODES.includes(errorCodeOf(error))) {
    // A blocked second recovery (loop guard) is ignored here; the original error still propagates.
    recoverSession().catch(() => {});
  }
  return Promise.reject(error);
};

export default axios => {
  const { apiHost = '' } = window.chatwootConfig || {};
  const wootApi = axios.create({ baseURL: `${apiHost}/` });
  // Add Auth Headers to requests if logged in
  if (Auth.hasAuthCookie()) {
    const {
      'access-token': accessToken,
      'token-type': tokenType,
      client,
      expiry,
      uid,
    } = Auth.getAuthData();
    Object.assign(wootApi.defaults.headers.common, {
      'access-token': accessToken,
      'token-type': tokenType,
      client,
      expiry,
      uid,
    });
  }
  // Response parsing interceptor
  wootApi.interceptors.response.use(
    response => response,
    error => parseErrorCode(error)
  );
  return wootApi;
};
