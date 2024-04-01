import {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifyAuthenticationResponseOpts,
  VerifyRegistrationResponseOpts,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { Request, Response } from "express";
import User from "../models/users";

import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  AuthenticatorDevice,
  PublicKeyCredentialDescriptorFuture,
  RegistrationResponseJSON,
} from "@simplewebauthn/types";

import { isoBase64URL, isoUint8Array } from "@simplewebauthn/server/helpers";

interface CustomSessionData {
  currentChallenge?: string;
  userId?: string;
}

declare module "express-session" {
  interface SessionData extends CustomSessionData {}
}

export const startRegistration = async (req: Request, res: Response) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ message: "Username is required" });
  }

  const existingUser = await User.findOne({
    username,
  });

  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  const user = new User({ username });
  await user.save();

  const opts: GenerateRegistrationOptionsOpts = {
    rpName: "SimpleWebAuthn Example",
    rpID: process.env.RP_ID || "localhost",
    userID: user._id.toString(),
    userName: username,
    timeout: 60000,
    attestationType: "none",
    // excludeCredentials: devices.map((dev) => ({
    //   id: dev.credentialID,
    //   type: "public-key",
    //   transports: dev.transports,
    // })),
    authenticatorSelection: {
      residentKey: "discouraged",
      /**
       * Wondering why user verification isn't required? See here:
       *
       * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
       */
      userVerification: "preferred",
    },
    /**
     * Support the two most common algorithms: ES256, and RS256
     */
    supportedAlgorithmIDs: [-7, -257],
  };

  const options = await generateRegistrationOptions(opts);

  req.session.currentChallenge = options.challenge;
  req.session.userId = user._id.toString();
  req.session.save((err) => {
    if (err) {
      console.error("Session save error:", err);
    }
    res.send(options);
  });
};

// note: User devices can be stored in a separate collection, but for simplicity, we're storing them in the User collection
export const finishRegistration = async (req: Request, res: Response) => {
  const body: RegistrationResponseJSON = req.body;

  console.log("session", JSON.stringify(req.session, null, 2));

  const expectedChallenge = req.session.currentChallenge;
  const userId = req.session.userId;

  const user = await User.findById(userId);

  let verification: VerifiedRegistrationResponse;

  try {
    const opts: VerifyRegistrationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin: process.env.ORIGIN || "http://localhost:3000",
      expectedRPID: process.env.RP_ID || "localhost",
      requireUserVerification: false,
    };
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified) {
    // @ts-ignore
    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    const existingDevice = user?.devices.find((device) =>
      isoUint8Array.areEqual(device.credentialID as any, credentialID)
    );

    if (!existingDevice) {
      const newDevice = {
        credentialPublicKey: Buffer.from(credentialPublicKey),
        credentialID: Buffer.from(credentialID),
        counter,
        transports: body.response.transports,
      };
      user?.devices.push(newDevice);
      await user?.save();
    }
  }

  req.session.currentChallenge = undefined;
  req.session.userId = undefined;
  req.session.save((err) => {
    if (err) {
      console.error("Session save error:", err);
    }
    res.send({ verified });
  });
};

export const startAuthentication = async (req: Request, res: Response) => {
  const { username } = req.body;

  const user = await User.findOne({
    username,
  });

  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  const allowCreds: PublicKeyCredentialDescriptorFuture[] = user.devices.map(
    (dev) => ({
      id: Uint8Array.from(dev.credentialID),
      type: "public-key",
      transports: dev.transports as AuthenticatorTransportFuture[],
    })
  );
  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    allowCredentials: allowCreds,
    userVerification: "preferred",
    rpID: process.env.RP_ID || "localhost",
  };

  const options = await generateAuthenticationOptions(opts);

  req.session.currentChallenge = options.challenge;
  req.session.userId = user._id.toString();
  req.session.save((err) => {
    if (err) {
      console.error("Session save error:", err);
    }
    res.send(options);
  });
};

export const finishAuthentication = async (req: Request, res: Response) => {
  const body: AuthenticationResponseJSON = req.body;

  const expectedChallenge = req.session.currentChallenge;
  const userId = req.session.userId;

  console.log("session", JSON.stringify(req.session, null, 2));

  const user = await User.findById(userId);

  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  let dbAuthenticator;
  const bodyCredIDBuffer = isoBase64URL.toBuffer(body.rawId);

  for (const dev of user.devices) {
    const credentialID = Uint8Array.from(dev.credentialID);
    if (isoUint8Array.areEqual(credentialID, bodyCredIDBuffer)) {
      dbAuthenticator = {
        counter: dev.counter,
        credentialID,
        credentialPublicKey: Uint8Array.from(dev.credentialPublicKey),
        transports: dev.transports as AuthenticatorTransportFuture[],
      };
      break;
    }
  }

  if (!dbAuthenticator) {
    return res.status(400).send({
      error: "Device is not registered with this site",
    });
  }

  let verification: VerifiedAuthenticationResponse;

  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin: process.env.ORIGIN || "http://localhost:3000",
      expectedRPID: process.env.RP_ID || "localhost",
      authenticator: dbAuthenticator,
      requireUserVerification: false,
    };
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update the authenticator's counter in the DB to the newest count in the authentication
    dbAuthenticator.counter = authenticationInfo.newCounter;
  }

  req.session.currentChallenge = undefined;
  req.session.userId = undefined;
  req.session.save((err) => {
    if (err) {
      console.error("Session save error:", err);
    }
    res.send({ verified });
  });
};
