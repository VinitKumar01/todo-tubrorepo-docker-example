import express, {
  type NextFunction,
  type Response,
  type Request,
} from "express";
import { prismaClient } from "@repo/db/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { configDotenv } from "dotenv";

configDotenv();

const app = express();

app.use(express.json());

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await prismaClient.user.create({
    data: {
      username,
      password: hashedPassword,
    },
  });

  if (user) {
    res.json({
      userId: user.id,
    });
  } else {
    res.status(401).json({
      error: "Error while creating the user",
    });
  }

  if (user) {
    res.json({
      message: "User created successfully",
    });
  } else {
    res.status(401).json({
      message: "Error while creating the user",
    });
  }
});

app.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  const user = await prismaClient.user.findUnique({
    where: {
      username,
    },
  });

  if (!user) {
    res.status(404).json({
      error: "No such user exists",
    });
  }

  const match = await bcrypt.compare(password, user?.password as string);

  const secret = process.env.JWT_SECRET;

  const token = jwt.sign(
    {
      id: user?.id,
      username: user?.username,
    },
    secret!,
  );

  if (!match) {
    res.status(401).json({
      error: "Invalid credentials",
    });
  }

  res.json({
    token,
  });
});

const middleware = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    res.status(401).json({
      error: "Missing token",
    });
  }

  const secret = process.env.JWT_SECRET;

  jwt.verify(token as string, secret!, (err, user) => {
    if (err) {
      return res.status(401).json({
        error: "Invalid token",
      });
    } else {
      req.body.userId = (user as jwt.JwtPayload)?.id;
      next();
    }
  });
};

app.post("/todo", middleware, async (req, res) => {
  const { task, done, userId } = req.body;

  const todo = await prismaClient.todo.create({
    data: {
      task,
      done: done,
      userId,
    },
  });

  if (todo) {
    res.json({
      todoId: todo.id,
    });
  } else {
    res.status(401).json({
      error: "Error while creating the todo",
    });
  }
});

app.get("/todo", middleware, async (req, res) => {
  const { userId } = req.body;
  const { todoId } = req.query;
  const todo = await prismaClient.todo.findUnique({
    where: {
      id: todoId as string,
      userId,
    },
    select: {
      task: true,
    },
  });

  if (!todo) {
    res.status(404).json({
      error: "No such todo found",
    });
  }

  res.json({
    todo,
  });
});

app.get("/", middleware, async (req, res) => {
  const { userId } = req.body;
  const todo = await prismaClient.todo.findMany({
    where: {
      userId,
    },
    select: {
      task: true,
    },
  });

  if (!todo) {
    res.status(404).json({
      error: "No such todo found",
    });
  }

  res.json({
    todo,
  });
});

app.listen(8080, () => {
  console.log("Listening to port 8080");
});
