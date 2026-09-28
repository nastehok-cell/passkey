import {NextFunction, Request, Response} from 'express';
import jwt from 'jsonwebtoken';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';
import CustomError from '../../classes/CustomError';
import AuthenticatorDeviceModel from '../models/authenticatorDeviceModel';
import ChallengeModel from '../models/challengeModel';
import PasskeyUserModel from '../models/passkeyUserModel';
import fetchData from '../../utils/fetchData';

// check environment variables
if (
  !process.env.NODE_ENV ||
  !process.env.RP_ID ||
  !process.env.AUTH_URL ||
  !process.env.JWT_SECRET ||
  !process.env.RP_NAME
) {
  throw new Error('Environment variables not set');
}

const {NODE_ENV, RP_ID, AUTH_URL, JWT_SECRET, RP_NAME} = process.env;

const getExpectedOrigin = () => {
  return NODE_ENV === 'production'
    ? 'https://passkey-client-starter.netlify.app'
    : 'http://localhost:5173';
};
const getUserFromAuthApi = async (email: string) => {
  const response = await fetchData<{
    user: {
      user_id: number;
      username: string;
      email: string;
    };
  }>(`${AUTH_URL}/users/email/${encodeURIComponent(email)}`);

  return response.user;
};



// Registration handler
const setupPasskey = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const {username, email, password} = req.body;

    if (!username || !email || !password) {
      throw new CustomError('Username, email and password are required', 400);
    }

    await fetchData(`${AUTH_URL}/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username,
        email,
        password,
      }),
    });

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: email,
      userDisplayName: username,
      timeout: 60000,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    await ChallengeModel.findOneAndUpdate(
      {email},
      {
        challenge: options.challenge,
        email,
      },
      {
        upsert: true,
        new: true,
      },
    );

    const user = await getUserFromAuthApi(email);

    await PasskeyUserModel.findOneAndUpdate(
      {email},
      {
        userId: user.user_id,
        email,
        devices: [],
      },
      {
        upsert: true,
        new: true,
      },
    );

    res.status(200).json({
      email,
      options,
      message: 'Registration options generated',
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Registration verification handler
const verifyPasskey = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const {email, ...response} = req.body as {
      email: string;
    } & RegistrationResponseJSON;

    const challenge = await ChallengeModel.findOne({email});

    if (!challenge) {
      throw new CustomError('Challenge not found', 400);
    }

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: getExpectedOrigin(),
      expectedRPID: RP_ID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw new CustomError('Passkey registration failed', 400);
    }

    const {credentialID, credentialPublicKey, counter} =
      verification.registrationInfo;

    const existingDevice = await AuthenticatorDeviceModel.findOne({
      credentialID,
    });

    if (existingDevice) {
      throw new CustomError('Passkey is already registered', 400);
    }

    const device = await AuthenticatorDeviceModel.create({
      email,
      credentialID,
      credentialPublicKey: Buffer.from(credentialPublicKey),
      counter,
      transports: response.response.transports ?? [],
    });

    await PasskeyUserModel.findOneAndUpdate(
      {email},
      {
        $push: {
          devices: device._id,
        },
      },
    );

    await ChallengeModel.deleteOne({email});

    const user = await getUserFromAuthApi(email);

    res.status(200).json({
      message: 'Passkey registered successfully',
      user,
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Generate authentication options handler
const authenticationOptions = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const {email} = req.body;

    const user = await PasskeyUserModel.findOne({email});

    if (!user) {
      throw new CustomError('User not found', 404);
    }

    const devices = await AuthenticatorDeviceModel.find({email});

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: devices.map((device) => ({
        id: device.credentialID,
        transports: device.transports,
      })),
      userVerification: 'preferred',
    });

    await ChallengeModel.findOneAndUpdate(
      {email},
      {
        challenge: options.challenge,
        email,
      },
      {
        upsert: true,
        new: true,
      },
    );

    res.status(200).json({
      email,
      options,
      message: 'Authentication options generated',
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Authentication verification and login handler
const verifyAuthentication = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const {email, ...response} = req.body as {
      email: string;
    } & AuthenticationResponseJSON;

    const challenge = await ChallengeModel.findOne({email});

    if (!challenge) {
      throw new CustomError('Challenge not found', 400);
    }

    const device = await AuthenticatorDeviceModel.findOne({
      email,
      credentialID: response.id,
    });

    if (!device) {
      throw new CustomError('Authenticator not found', 404);
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: getExpectedOrigin(),
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: device.credentialID,
        credentialPublicKey: new Uint8Array(device.credentialPublicKey),
        counter: device.counter,
        transports: device.transports,
      },
    });

    if (!verification.verified) {
      throw new CustomError('Authentication failed', 401);
    }

    device.counter = verification.authenticationInfo.newCounter;

    await device.save();

    await ChallengeModel.deleteOne({email});

    const user = await getUserFromAuthApi(email);

    const token = jwt.sign(
      {
        user_id: user.user_id,
        email: user.email,
      },
      JWT_SECRET,
      {
        expiresIn: '1h',
      },
    );

    res.status(200).json({
      message: 'Authentication successful',
      token,
      user,
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {
  setupPasskey,
  verifyPasskey,
  authenticationOptions,
  verifyAuthentication,
};
