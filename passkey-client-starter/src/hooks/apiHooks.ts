import fetchData from '@/lib/fetchData';
import {LoginResponse, UserResponse} from '@sharedTypes/MessageTypes';
import {User} from '@sharedTypes/DBTypes';
import {
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser';

const useUser = () => {
  const getUserByToken = async (token: string) => {
    const options = {
      headers: {
        Authorization: 'Bearer ' + token,
      },
    };

    return await fetchData<UserResponse>(
      import.meta.env.VITE_AUTH_API + '/users/token/',
      options,
    );
  };

  const getUsernameAvailable = async (username: string) => {
    return await fetchData<{available: boolean}>(
      import.meta.env.VITE_AUTH_API + '/users/username/' + username,
    );
  };

  const getEmailAvailable = async (email: string) => {
    return await fetchData<{available: boolean}>(
      import.meta.env.VITE_AUTH_API + '/users/email/' + email,
    );
  };

  return {
    getUserByToken,
    getUsernameAvailable,
    getEmailAvailable,
  };
};

const usePasskey = () => {
  const postUser = async (user: User) => {
    const options = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(user),
    };

    const setupResponse = await fetchData<{
      email: string;
      options: Parameters<typeof startRegistration>[0];
      message: string;
    }>(
      import.meta.env.VITE_PASSKEY_API + '/register',
      options,
    );

    const registrationResponse = await startRegistration(
      setupResponse.options,
    );

    const verificationResponse = await fetchData<UserResponse>(
      import.meta.env.VITE_PASSKEY_API + '/register/verify',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: setupResponse.email,
          ...registrationResponse,
        }),
      },
    );

    return verificationResponse;
  };

  const postLogin = async (email: string) => {
    const setupResponse = await fetchData<{
      email: string;
      options: Parameters<typeof startAuthentication>[0];
      message: string;
    }>(
      import.meta.env.VITE_PASSKEY_API + '/authentication-options',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
        }),
      },
    );

    const authenticationResponse = await startAuthentication(
      setupResponse.options,
    );

    const loginResponse = await fetchData<LoginResponse>(
      import.meta.env.VITE_PASSKEY_API + '/authentication',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: setupResponse.email,
          ...authenticationResponse,
        }),
      },
    );

    return loginResponse;
  };

  return {postUser, postLogin};
};

export {useUser, usePasskey};
