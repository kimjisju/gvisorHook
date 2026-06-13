const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const pool = require("./db");
const crypto = require("crypto");
const sendEmail = require("./utils/sendEmail");

require("dotenv").config();

const app = express();
const sseClients = new Set();

app.use(cors());
app.use(express.json());

function broadcastGuardRun(payload) {
  const message = `data: ${JSON.stringify(payload)}\n\n`;

  for (const client of sseClients) {
    client.write(message);
  }
}

app.get("/", (req, res) => {
  res.send("Backend server is running");
});

app.get("/test-mail", async (req, res) => {
  try {
    await sendEmail(
      "네가받을이메일@gmail.com",
      "테스트 메일",
      "<h1>메일 정상 작동</h1>"
    );

    res.send("메일 전송 성공");
  } catch (err) {
    console.error(err);
    res.status(500).send("메일 전송 실패");
  }
});

// 회원가입 API
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "이름, 이메일, 비밀번호를 모두 입력해주세요.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 1000 * 60 * 30);

    await pool.query(
      `INSERT INTO users
       (name, email, password_hash, is_verified, verification_token, verification_token_expires)
       VALUES ($1, $2, $3, false, $4, $5)`,
      [name, email, hashedPassword, verificationToken, expires]
    );

    const verifyLink = `${process.env.BACKEND_URL}/verify-email?token=${verificationToken}`;

    await sendEmail(
      email,
      "이메일 인증을 완료해주세요",
      `
      <h2>이메일 인증</h2>
      <p>아래 링크를 클릭해서 회원가입을 완료해주세요.</p>
      <a href="${verifyLink}">이메일 인증하기</a>
      <p>이 링크는 30분 후 만료됩니다.</p>
      `
    );

    res.status(201).json({
      message: "회원가입 성공. 이메일 인증을 진행해주세요.",
    });
  } catch (err) {
    console.error(err);

    if (err.code === "23505") {
      return res.status(409).json({
        error: "이미 가입된 이메일입니다.",
      });
    }

    res.status(500).json({
      error: "서버 오류가 발생했습니다.",
    });
  }
});

// 이메일 인증 API
app.get("/verify-email", async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).send("인증 토큰이 없습니다.");
    }

    const result = await pool.query(
      `SELECT * FROM users
       WHERE verification_token = $1
       AND verification_token_expires > NOW()`,
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(400).send("인증 링크가 유효하지 않거나 만료되었습니다.");
    }

    await pool.query(
      `UPDATE users
       SET is_verified = true,
           verification_token = null,
           verification_token_expires = null
       WHERE verification_token = $1`,
      [token]
    );

    res.send(`
      <h2>이메일 인증 완료</h2>
      <p>이제 로그인할 수 있습니다.</p>
      <a href="${process.env.FRONTEND_URL}/login">로그인하러 가기</a>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send("이메일 인증 중 오류가 발생했습니다.");
  }
});

// 로그인 API
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "이메일과 비밀번호를 입력해주세요.",
      });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "이메일 또는 비밀번호가 틀렸습니다.",
      });
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({
        error: "이메일 또는 비밀번호가 틀렸습니다.",
      });
    }

    if (!user.is_verified) {
      return res.status(403).json({
        error: "이메일 인증 후 로그인할 수 있습니다.",
      });
    }

    res.json({
      message: "로그인 성공",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "서버 오류가 발생했습니다.",
    });
  }
});

// Guard run 저장 API
app.post("/guard-runs", async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      user_id,
      agent_name,
      user_prompt,
      ai_agent_reasoning,
      rule_base_result,
      rule_base_reason,
      guard_llm_result,
      guard_llm_reason,
      final_decision,
      approval_status,
      actions = [],
    } = req.body;

    if (!agent_name || !user_prompt || !final_decision) {
      return res.status(400).json({
        error: "agent_name, user_prompt, final_decision은 필수입니다.",
      });
    }

    await client.query("BEGIN");

    const runResult = await client.query(
      `INSERT INTO guard_runs
       (
         user_id,
         agent_name,
         user_prompt,
         ai_agent_reasoning,
         rule_base_result,
         rule_base_reason,
         guard_llm_result,
         guard_llm_reason,
         final_decision,
         approval_status
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, COALESCE($10, 'pending'))
       RETURNING *`,
      [
        user_id ?? null,
        agent_name,
        user_prompt,
        ai_agent_reasoning ?? null,
        rule_base_result ?? null,
        rule_base_reason ?? null,
        guard_llm_result ?? null,
        guard_llm_reason ?? null,
        final_decision,
        approval_status ?? null,
      ]
    );

    const guardRun = runResult.rows[0];

    const insertedActions = [];

    for (let index = 0; index < actions.length; index += 1) {
      const action = actions[index];

      const actionResult = await client.query(
        `INSERT INTO guard_actions
         (
           run_id,
           action_order,
           agent_name,
           event_id,
           created_at,
           syscall,
           path,
           argv,
           raw_summary,
           summary,
           meaning,
           normalized_action,
           target_class,
           rule_result
         )
         VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
         )
         RETURNING *`,
        [
          guardRun.id,
          action.action_order ?? index + 1,
          action.agent_name ?? agent_name,
          action.event_id ?? null,
          action.created_at ?? null,
          action.syscall ?? null,
          action.path ?? null,
          action.argv ?? null,
          action.raw_summary ?? null,
          action.summary ?? null,
          action.meaning ?? null,
          action.normalized_action ?? null,
          action.target_class ?? null,
          action.rule_result ?? null,
        ]
      );

      insertedActions.push(actionResult.rows[0]);
    }

    await client.query("COMMIT");

    broadcastGuardRun({
      type: "guard-run-created",
      run: guardRun,
      actions: insertedActions,
    });

    res.status(201).json({
      message: "guard run 저장 성공",
      run: guardRun,
      actions: insertedActions,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.status(500).json({
      error: "guard run 저장 중 오류가 발생했습니다.",
    });
  } finally {
    client.release();
  }
});

// Guard run 목록 조회 API
app.get("/guard-runs", async (req, res) => {
  try {
    const { user_id } = req.query;
    const queryParams = [];
    let whereClause = "";

    if (user_id !== undefined) {
      const parsedUserId = Number(user_id);

      if (!Number.isInteger(parsedUserId) || parsedUserId <= 0) {
        return res.status(400).json({
          error: "user_id는 양의 정수여야 합니다.",
        });
      }

      queryParams.push(parsedUserId);
      whereClause = "WHERE gr.user_id = $1";
    }

    const result = await pool.query(
      `SELECT
         gr.*,
         COALESCE(
           json_agg(
             json_build_object(
               'id', ga.id,
               'run_id', ga.run_id,
               'action_order', ga.action_order,
               'agent_name', ga.agent_name,
               'event_id', ga.event_id,
               'created_at', ga.created_at,
               'syscall', ga.syscall,
               'path', ga.path,
               'argv', ga.argv,
               'raw_summary', ga.raw_summary,
               'summary', ga.summary,
               'meaning', ga.meaning,
               'normalized_action', ga.normalized_action,
               'target_class', ga.target_class,
               'rule_result', ga.rule_result
             )
             ORDER BY ga.action_order ASC, ga.id ASC
           ) FILTER (WHERE ga.id IS NOT NULL),
           '[]'::json
         ) AS actions
       FROM guard_runs gr
       LEFT JOIN guard_actions ga ON ga.run_id = gr.id
       ${whereClause}
       GROUP BY gr.id
       ORDER BY gr.created_at DESC, gr.id DESC`,
      queryParams
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "guard run 목록 조회 중 오류가 발생했습니다.",
    });
  }
});

// Guard run 상세 조회 API
app.get("/guard-runs/stream", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  res.write(`data: ${JSON.stringify({ type: "connected" })}\n\n`);
  sseClients.add(res);

  req.on("close", () => {
    sseClients.delete(res);
  });
});

app.get("/guard-runs/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const runResult = await pool.query(
      `SELECT *
       FROM guard_runs
       WHERE id = $1`,
      [id]
    );

    if (runResult.rows.length === 0) {
      return res.status(404).json({
        error: "guard run을 찾을 수 없습니다.",
      });
    }

    const actionsResult = await pool.query(
      `SELECT *
       FROM guard_actions
       WHERE run_id = $1
       ORDER BY action_order ASC, id ASC`,
      [id]
    );

    res.json({
      run: runResult.rows[0],
      actions: actionsResult.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "guard run 상세 조회 중 오류가 발생했습니다.",
    });
  }
});

// Guard run 승인 상태 변경 API
app.patch("/guard-runs/:id/approval", async (req, res) => {
  try {
    const { id } = req.params;
    const { approval_status, approved_by } = req.body;

    const allowedStatuses = ["pending", "approved", "rejected"];

    if (!allowedStatuses.includes(approval_status)) {
      return res.status(400).json({
        error: "approval_status는 pending, approved, rejected 중 하나여야 합니다.",
      });
    }

    const approvedAt =
      approval_status === "pending" ? null : new Date();
    const approvedBy =
      approval_status === "pending" ? null : approved_by ?? null;

    const result = await pool.query(
      `UPDATE guard_runs
       SET approval_status = $1,
           approved_by = $2,
           approved_at = $3
       WHERE id = $4
       RETURNING *`,
      [approval_status, approvedBy, approvedAt, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "guard run을 찾을 수 없습니다.",
      });
    }

    broadcastGuardRun({
      type: "guard-run-updated",
      run: result.rows[0],
    });

    res.json({
      message: "approval 상태 변경 성공",
      run: result.rows[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "approval 상태 변경 중 오류가 발생했습니다.",
    });
  }
});

app.listen(process.env.PORT || 5000, () => {
  console.log(`Server running on port ${process.env.PORT || 5000}`);
});
