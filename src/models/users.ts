import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  devices: [
    {
      credentialID: { type: Buffer, required: true }, // todo: fix the type
      credentialPublicKey: { type: Buffer, required: true },
      counter: { type: Number, default: 0 },
      transports: [String],
    },
  ],
});

const User = mongoose.model("User", userSchema);
export default User;
