import express from "express";
import cors from "cors";
import Joi from "joi";
import { Sequelize } from "sequelize";
import DataTypes from "sequelize";
import { Snowflake } from "@theinternetfolks/snowflake";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const port = 3000 || process.env.PORT;
const SECRET_KEY = "secret123456";

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

const sequelize = new Sequelize(
  "postgres://postgres:postgrespw@localhost:5432/nama",
);
const User = sequelize.define("User", {
  id: {
    type: DataTypes.STRING,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
});

const Community = sequelize.define("Community", {
  id: {
    type: DataTypes.STRING,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  slug: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false,
  },
});

const Role = sequelize.define("role", {
  id: {
    type: DataTypes.STRING,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
});

const Member = sequelize.define("member", {
  id: {
    type: DataTypes.STRING,
    primaryKey: true,
  },
});

Community.belongsTo(User, { foreignKey: "owner_id", as: "owner" });
Member.belongsTo(User, { foreignKey: "user_id", as: "user" });
Member.belongsTo(Community, { foreignKey: "community_id", as: "community" });
Member.belongsTo(Role, { foreignKey: "role_id", as: "role" });

function getsuccessStruct(data) {
  return {
    status: true,
    content: data,
  };
}

function getErrorStruct(errors) {
  return {
    status: false,
    errors,
  };
}

async function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res
      .status(401)
      .json(
        getErrorStruct([
          { message: "You need to sign in to proceed", code: "NOT_SIGNEDIN" },
        ]),
      );
  }
  const token = authHeader && authHeader.split(" ")[1];
  console.log(token, "Token");
  if (token === null) {
    return res
      .status(401)
      .json(
        getErrorStruct([
          { message: "You need to sign in to proceed", code: "NOT_SIGNEDIN" },
        ]),
      );
  }
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .json(
          getErrorStruct([
            { message: "You need to sign in to proceed", code: "NOT_SIGNEDIN" },
          ]),
        );
    }
    req.decoded = User.findOne({ where: { id: decoded.id } }).then(
      (user) => user,
    );
    next();
  });
}

app.delete("/v1/member/:id", authenticateToken, async (req, res) => {
  const user = await req.decoded;
  const victim_id = req.params.id;
  const victim = await Member.findOne({ where: { id: victim_id } });
  if (!victim) {
    res.json(
      getErrorStruct([
        {
          message: "Member not found.",
          code: "RESOURCE_NOT_FOUND",
        },
      ]),
    );
    return;
  }
  const myMember = await Member.findOne({
    where: { community_id: victim.community_id, user_id: user.id },
  });
  if (!myMember) {
    res.json(
      getErrorStruct([
        {
          message: "You are not authorized to perform this action.",
          code: "NOT_ALLOWED_ACCESS",
        },
      ]),
    );
    return;
  }
  const myRole = await Role.findOne({ where: { id: myMember.role_id } });
  if (!myRole) {
    res.json(
      getErrorStruct([
        {
          message: "You are not authorized to perform this action.",
          code: "NOT_ALLOWED_ACCESS",
        },
      ]),
    );
    return;
  }
  if (
    myRole.name !== "Community Admin" ||
    myRole.name !== "Community Moderator"
  ) {
    res.json(
      getErrorStruct([
        {
          message: "You are not authorized to perform this action.",
          code: "NOT_ALLOWED_ACCESS",
        },
      ]),
    );
    return;
  }
  await Member.destroy({ where: { id: victim_id } });
  res.status(200).json({ status: true });
});

app.post("/v1/member", authenticateToken, async (req, res) => {
  const user = await req.decoded;
  const community_id = req.body.community;
  const new_user_id = req.body.user;
  const role_id = req.body.role;
  const community = await Community.findOne({ where: { id: community_id } });
  if (!community) {
    res.json(
      getErrorStruct([
        {
          param: "community",
          message: "Community not found.",
          code: "RESOURCE_NOT_FOUND",
        },
      ]),
    );
    return;
  }
  if (community.owner_id !== user.id) {
    res.json(
      getErrorStruct([
        {
          message: "You are not authorized to perform this action.",
          code: "NOT_ALLOWED_ACCESS",
        },
      ]),
    );
    return;
  }
  const new_user = await User.findOne({ where: { id: new_user_id } });
  if (!new_user) {
    res.json(
      getErrorStruct([
        {
          param: "user",
          message: "User not found.",
          code: "RESOURCE_NOT_FOUND",
        },
      ]),
    );
    return;
  }
  const role = await Role.findOne({ where: { id: role_id } });
  if (!role) {
    res.json(
      getErrorStruct([
        {
          param: "role",
          message: "Role not found.",
          code: "RESOURCE_NOT_FOUND",
        },
      ]),
    );
    return;
  }
  const exists = await Member.findOne({
    where: { user_id: new_user_id, community_id },
  });
  if (exists) {
    res.json(
      getErrorStruct([
        {
          message: "User is already added in the community",
          code: "RESOURCE_EXISTS",
        },
      ]),
    );
    return;
  }
  const new_member = await Member.create({
    id: Snowflake.generate(),
    community_id,
    user_id: new_user_id,
    role_id,
  });
  res.json(getsuccessStruct({ data: new_member }));
});

app.post("/v1/role", (req, res) => {
  const { name } = req.body;
  const validationErr = Joi.string()
    .min(2)
    .required()
    .validate(name, { abortEarly: false });
  if (validationErr.error) {
    res.json(
      getErrorStruct([
        validationErr.error.details.map((error) => {
          return {
            param: error.context.key,
            message: error.message,
            code: "INVALID_INPUT",
          };
        }),
      ]),
    );
    return;
  }
  Role.create({ id: Snowflake.generate(), name })
    .then((role) => {
      res.json(getsuccessStruct({ data: role }));
    })
    .catch((e) => {
      console.log(e);
      res.json(
        getErrorStruct([
          {
            param: "name",
            message: "Role with this name already exists",
            code: "RESOURCE_EXISTS",
          },
        ]),
      );
    });
});

app.get("/v1/role", (req, res) => {
  let { page } = req.query;
  if (page === undefined || page < 0) {
    page = 0;
  }
  Role.findAndCountAll({ limit: 10, offset: page * 10, where: {} }).then(
    (roles) => {
      res.json(
        getsuccessStruct({
          meta: {
            page: page + 1,
            total: roles.count,
            pages: parseInt(roles.count / 10) + 1,
          },
          data: roles.rows,
        }),
      );
    },
  );
});

app.post("/v1/community", authenticateToken, async (req, res) => {
  const user = await req.decoded;
  console.log(user);
  const { name } = req.body;
  if (name === undefined || name.length <= 2) {
    res.json(
      getErrorStruct({
        param: "name",
        message: "Name must be at least 2 characters long",
        code: "INVALID_INPUT",
      }),
    );
  } else {
    const user_id = user.id;
    console.log(user_id, "User ID");
    const community = await Community.create({
      id: Snowflake.generate(),
      name,
      slug: name.toLowerCase(),
      owner_id: user_id,
    });
    const admin = await Role.findOne({ where: { name: "Community Admin" } });
    Member.create({
      id: Snowflake.generate(),
      user_id: user_id,
      community_id: community.id,
      role_id: admin.id,
    });
    res.json(getsuccessStruct({ data: community }));
  }
});

app.get("/v1/community", async (req, res) => {
  const user = await req.decoded;
  let { page } = req.query;
  if (page === undefined || page < 0) {
    page = 0;
  }
  Community.findAndCountAll({
    limit: 10,
    offset: page * 10,
    where: {},
    include: [
      {
        model: User,
        as: "owner",
        attributes: ["id", "name"],
      },
    ],
    attributes: { exclude: ["owner_id"] },
  }).then((communities) => {
    res.json(
      getsuccessStruct({
        meta: {
          page: page + 1,
          total: communities.count,
          pages: parseInt(communities.count / 10) + 1,
        },
        data: communities.rows,
      }),
    );
  });
});

app.get("/v1/community/:id/members", (req, res) => {
  let { page } = req.query;
  if (page === undefined || page < 0) {
    page = 0;
  }
  Member.findAndCountAll({
    limit: 10,
    offset: page * 10,
    where: { community_id: req.params.id },
    attributes: ["id", ["community_id", "community"], "createdAt"],
    include: [
      {
        model: User,
        required: true,
        attributes: ["id", "name"],
        as: "user",
      },
      {
        model: Role,
        required: true,
        attributes: ["id", "name"],
        as: "role",
      },
    ],
  }).then((members) => {
    res.json(
      getsuccessStruct({
        meta: {
          page: page + 1,
          total: members.count,
          pages: parseInt(members.count / 10) + 1,
        },
        data: members.rows,
      }),
    );
  });
});

app.get("/v1/community/me/owner", authenticateToken, async (req, res) => {
  const user = await req.decoded;
  let { page } = req.query;
  if (page === undefined || page < 0) {
    page = 0;
  }
  Community.findAndCountAll({
    where: { owner_id: user.id },
  }).then((communities) => {
    res.json(
      getsuccessStruct({
        meta: {
          page: page + 1,
          total: communities.count,
          pages: parseInt(communities.count / 10) + 1,
        },
        data: communities.rows,
      }),
    );
  });
});

app.get("/v1/community/me/member", authenticateToken, async (req, res) => {
  const user = await req.decoded;
  let { page } = req.query;
  if (page === undefined || page < 0) {
    page = 0;
  }
  Member.findAndCountAll({
    where: { user_id: user.id },
    include: [
      {
        model: Community,
        required: true,
        attributes: { exclude: ["owner_id"] },
        as: "community",
        include: [
          {
            model: User,
            required: true,
            attributes: ["id", "name"],
            as: "owner",
          },
        ],
      },
    ],
  }).then((members) => {
    res.json(
      getsuccessStruct({
        meta: {
          page: page + 1,
          total: members.count,
          pages: parseInt(members.count / 10) + 1,
        },
        data: members.rows.map((member) => member["community"]),
      }),
    );
  });
});

app.get("/v1/auth/me", authenticateToken, async (req, res) => {
  const user = await req.decoded;
  if (!user) {
    return res
      .status(401)
      .json(
        getErrorStruct([
          { message: "You need to sign in to proceed", code: "NOT_SIGNEDIN" },
        ]),
      );
  }
  User.findOne({
    where: { id: user.id },
    attributes: { exclude: ["password", "updatedAt"] },
  }).then((user) => {
    res.json(getsuccessStruct({ data: user }));
  });
});

const userSignupSchema = Joi.object({
  name: Joi.string().min(2).required(),
  password: Joi.string().min(6).required(),
  email: Joi.string().email().required(),
});

app.post("/v1/auth/signup", (req, res) => {
  console.log(req.body);
  const { name, password, email } = req.body;
  const validation_res = userSignupSchema.validate(req.body, {
    abortEarly: false,
  });
  if (validation_res.error) {
    res.json(
      getErrorStruct([
        validation_res.error.details.map((error) => {
          return {
            param: error.context.key,
            message: error.message,
            code: "INVALID_INPUT",
          };
        }),
      ]),
    );
    return;
  }
  const hashedPassword = bcrypt.hashSync(password, 10);
  User.create({
    id: Snowflake.generate(),
    name,
    password: hashedPassword,
    email,
  })
    .then((user) => {
      const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: "1h" });
      res.json(
        getsuccessStruct({
          data: {
            id: user.id,
            name: user.name,
            email: user.email,
            created_at: user.createdAt,
          },
          meta: {
            access_token: token,
          },
        }),
      );
    })
    .catch((e) => {
      console.log(e);
      res.json(
        getErrorStruct([
          {
            param: "email",
            message: "User with this email address already exists.",
            code: "RESOURCE_EXISTS",
          },
        ]),
      );
    });
});

const userSigninSchema = Joi.object({
  password: Joi.string().min(6).required(),
  email: Joi.string().email().required(),
});
app.post("/v1/auth/signin", (req, res) => {
  const { email, password } = req.body;
  const validation_res = userSigninSchema.validate(req.body, {
    abortEarly: false,
  });
  if (validation_res.error) {
    res.json(
      getErrorStruct([
        validation_res.error.details.map((error) => {
          return {
            param: error.context.key,
            message: error.message,
            code: "INVALID_INPUT",
          };
        }),
      ]),
    );
    return;
  }
  User.findOne({ where: { email } }).then((user) => {
    if (!user) {
      res.json(
        getErrorStruct([
          {
            param: "password",
            message: "The credentials you provided are invalid.",
            code: "INVALID_CREDENTIALS",
          },
        ]),
      );
      return;
    }
    bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        const token = jwt.sign({ id: user.id }, SECRET_KEY, {
          expiresIn: "1h",
        });
        res.json(
          getsuccessStruct({
            data: {
              id: user.id,
              name: user.name,
              email: user.email,
              created_at: user.created_at,
            },
            meta: {
              access_token: token,
            },
          }),
        );
      } else {
        res.json(
          getErrorStruct([
            {
              param: "password",
              message: "The credentials you provided are invalid.",
              code: "INVALID_CREDENTIALS",
            },
          ]),
        );
      }
    });
  });
});

app.listen(port, async () => {
  try {
    await sequelize.authenticate();
    // await sequelize.sync({ force: true });
    console.log("Connection has been established successfully.");
  } catch (error) {
    console.error("Unable to connect to the database:", error);
  }
  console.log(`API Listening on port ${port}`);
});
