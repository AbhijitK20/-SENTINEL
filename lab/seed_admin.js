// Seed the lab admin Idurar expects. Idurar 4.1.0 ships no signup route, so a
// fresh Mongo volume has no way in and /login always 401s. Uses the app's own
// mongoose + bcrypt so the stored hash is exactly what the login controller
// verifies against.
require('module-alias/register');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
// Load the app's own models so the collection names are mongoose's, never
// hand-guessed: Admin -> admins, AdminPassword -> adminpasswords.
require('@/models/coreModels/Admin');
require('@/models/coreModels/AdminPassword');

(async () => {
  const uri = process.env.DATABASE;
  if (!uri) throw new Error('DATABASE env var is not set');
  await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000 });

  const db = mongoose.connection.db;
  // Mongoose pluralises model names: Admin -> admins, AdminPassword ->
  // adminpasswords. Seeding the singular names silently creates collections the
  // app never reads, so /login reports "no account with this email".
  const Admins = mongoose.connection.collections.admins;
  const AdminPasswords = mongoose.connection.collections.adminpasswords;
  if (!Admins || !AdminPasswords) {
    throw new Error(
      'expected mongoose collections admins/adminpasswords, got: ' +
        Object.keys(mongoose.connection.collections).join(',')
    );
  }
  const email = 'admin@admin.com';
  const password = 'admin123';

  const existing = await Admins.findOne({ email });
  if (existing) {
    console.log('admin already present, nothing to do');
  } else {
    const now = new Date();
    const { insertedId } = await Admins.insertOne({
      removed: false,
      enabled: true,
      email,
      name: 'admin',
      surname: 'lab',
      role: 'admin',
      loggedInStatus: false,
      createdAt: now,
    });
    // Idurar verifies with bcrypt.compare(salt + password, storedHash), so the
    // stored value is the hash of the *concatenation*, not of the password.
    const salt = bcrypt.hashSync('sentinel-lab-salt', 10);
    await AdminPasswords.insertOne({
      removed: false,
      user: insertedId,
      password: bcrypt.hashSync(salt + password, 10),
      salt,
      emailVerified: true,
      requireNewPassword: false,
      authType: 'email',
      createdAt: now,
    });
    console.log(`seeded ${email} / ${password}`);
  }
  await mongoose.disconnect();
})().catch((e) => {
  console.error('seed failed:', e.message);
  process.exit(1);
});
