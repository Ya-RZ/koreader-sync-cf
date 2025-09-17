use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasm_bindgen::JsValue;
use worker::*;

#[derive(Deserialize, Debug, Serialize, Default, Clone)]
struct Progress {
    device_id: String,
    device: String,
    percentage: f64,
    progress: String,
    document: String,
    timestamp: u64,
}

#[derive(Debug, Default, Clone, Deserialize)]
struct User {
    username: String,
    password: String,
}

fn extract_user(req: &mut Request) -> Option<User> {
    let mut user = User::default();
    if let Ok(Some(name)) = req.headers().get("X-Auth-User") {
        if name.is_empty() {
            return None;
        }
        user.username = name;
    } else {
        return None;
    }
    if let Ok(Some(pw)) = req.headers().get("X-Auth-Key") {
        if pw.is_empty() {
            return None;
        }
        user.password = pw;
    } else {
        return None;
    }
    Some(user)
}

//注册账号
async fn register(req: &mut Request, db: D1Database) -> Result<Response> {
    let user: User = req.json::<User>().await?;
    let username = user.username;
    let password = user.password;
    if password.is_empty() || username.is_empty() {
        return Ok(Response::builder().with_status(400).empty());
    }
    //检查当前用户是否已经注册
    let st = db.prepare("SELECT ID FROM USER WHERE NAME=?1;");
    let query = st.bind(&[username.clone().into()])?;
    let id = query.first::<u64>(Some("ID")).await?;
    if id.is_some() {
        console_warn!("不可重复注册：{}", username);
        return Response::error("账号重复", 401);
    }
    //开始注册用户
    let st = db.prepare("INSERT INTO USER (NAME,PASSWORD) VALUES (?1,?2);");
    let query = st.bind(&[username.clone().into(), password.clone().into()])?;
    if let Ok(d1) = query.run().await {
        if d1.success() {
            return Response::builder().with_status(201).from_json(&json!({
                "username":username,
                "password":password
            }));
        }
        console_error!("注册失败：{:?}", d1.error());
    }
    Ok(Response::builder().with_status(500).empty())
}

//验证账号
async fn authorize(req: &mut Request, db: D1Database) -> Result<Response> {
    if let Some(user) = extract_user(req) {
        let username = user.username;
        let password = user.password;
        //检查当前用户是否已经注册
        let st = db.prepare("SELECT ID FROM USER WHERE NAME=?1 AND PASSWORD=?2;");
        let query = st.bind(&[username.clone().into(), password.into()])?;
        let id = query.first::<u64>(Some("ID")).await?;
        if id.is_some() {
            return ResponseBuilder::new()
                .with_status(200)
                .from_json(&json!({"authorized":"OK"}));
        }
        console_warn!("用户不存在或者账号信息错误：{}", username);
        return Response::error("账号错误", 401);
    }
    console_warn!("参数错误");
     Response::error("参数错误", 401)
}

//获取进度
async fn get_progress(req: &mut Request, db: D1Database, document: &String) -> Result<Response> {
    let user = extract_user(req);
    if user.is_none() {
        return Ok(Response::builder().with_status(401).empty());
    }
    let user = user.unwrap();
    let username = user.username;
    let password = user.password;
    //检查当前用户是否已经注册
    let st = db.prepare("SELECT ID FROM USER WHERE NAME=?1 AND PASSWORD=?2;");
    let query = st.bind(&[username.clone().into(), password.into()])?;
    let id = query.first::<u64>(Some("ID")).await?;
    if id.is_none() {
        console_warn!("用户不存在或信息错误：{}", username);
        return Ok(Response::builder().with_status(401).empty());
    }
    let sql = format!(
        "SELECT DEVICE_ID,DEVICE,PERCENTAGE,PROGRESS,DOCUMENT,TIMESTAMP FROM PROGRESS WHERE USER_ID={} AND DOCUMENT=?1 LIMIT 1;",
        id.unwrap()
    );
    let st = db.prepare(sql);
    let query = st.bind(&[document.into()])?;
    if let Ok(r) = query.raw::<Value>().await {
        if r.is_empty() {
            return Ok(Response::builder().with_status(404).empty());
        }
        let row = r.first().unwrap();
        let progress = Progress {
            device_id: row.first().unwrap().as_str().unwrap().to_string(),
            device: row.get(1).unwrap().as_str().unwrap().to_string(),
            percentage: row.get(2).unwrap().as_f64().unwrap(),
            progress: row.get(3).unwrap().as_str().unwrap().to_string(),
            document: row.get(4).unwrap().as_str().unwrap().to_string(),
            timestamp: row.get(5).unwrap().as_u64().unwrap(),
        };
        return Response::builder().with_status(200).from_json(&progress);
    }
    Ok(ResponseBuilder::new().with_status(200).empty())
}

//同步进度
async fn update_progress(req: &mut Request, db: D1Database) -> Result<Response> {
    let user = extract_user(req);
    if user.is_none() {
        return Ok(Response::builder().with_status(401).empty());
    }
    let user = user.unwrap();
    let username = user.username;
    let password = user.password;
    console_log!("username: {}", username);
    //检查当前用户是否已经注册
    let st = db.prepare("SELECT ID FROM USER WHERE NAME=?1 AND PASSWORD=?2 LIMIT 1;");
    let query = st.bind(&[username.clone().into(), password.into()])?;
    let rows = query.raw::<Value>().await?;
    if rows.is_empty() {
        console_warn!("用户不存在：{}", username);
        return Ok(Response::builder().with_status(401).empty());
    }
    let row = rows.first().unwrap();
    console_log!("用户ID：{:?}", row);
    let id = row.first().unwrap().as_u64();
    if id.is_none() {
        console_warn!("用户不存在：{}", username);
        return Ok(Response::builder().with_status(401).empty());
    }
    let user_id = id.unwrap();
    let body = req.text().await?;
    console_log!("body：{}", body);
    let value: Value = serde_json::from_str(&body)?;
    console_log!("同步进度：{:?}", value);

    let document = value.get("document").unwrap().as_str().unwrap();
    let progress = value.get("progress").unwrap().as_str().unwrap();
    let device_id = value.get("device_id").unwrap().as_str().unwrap();
    let percentage = value.get("percentage").unwrap().as_f64().unwrap();
    let device = value.get("device").unwrap().as_str().unwrap();
    // 先检查当前用户是否有该document的进度信息，有则更新，无则添加
    let sql = format!(
        "SELECT ID FROM PROGRESS WHERE USER_ID={} AND DOCUMENT=?1 LIMIT 1;",
        user_id
    );
    let st = db.prepare(sql);
    let query = st.bind(&[document.into()])?;
    let timestamp = (js_sys::Date::now() as u64) / 1000;
    //   let duration_since_epoch =time:: Duration::milliseconds(now_ms as i64);
    // 3. time 库的 UNIX_EPOCH 是一个 UTC 的 OffsetDateTime
    // let timestamp =time:: OffsetDateTime::UNIX_EPOCH + duration_since_epoch;
    if let Ok(Some(progress_id)) = query.first::<u64>(Some("ID")).await {
        console_log!("进度ID：{}", progress_id);
        let sql = format!(
            "UPDATE PROGRESS SET DEVICE_ID=?1,DEVICE=?2,PERCENTAGE=?3,PROGRESS=?4,TIMESTAMP={} WHERE ID={};",
            timestamp, progress_id
        );
        let update = db.prepare(sql);
        let exe = update.bind(&[
            device_id.into(),
            device.into(),
            percentage.into(),
            progress.into(),
        ]);
        match exe {
            Ok(state) => match state.run().await {
                Ok(r) => {
                    if r.success() {
                         Response::builder()
                            .with_status(200)
                            .from_json(&serde_json::json!(
                                {
                                    "document":document,
                                    "timestamp":timestamp
                                }
                            ))
                    } else {
                        console_log!("更新失败，返回错误响应");
                         Ok(Response::builder().with_status(500).empty())
                    }
                }
                Err(e) => {
                    console_error!("sql执行失败：{}", e);
                     Ok(Response::builder().with_status(500).empty())
                }
            },
            Err(e) => {
                console_error!("sql语句处理失败：{}", e);
                 Ok(Response::builder().with_status(500).empty())
            }
        }
    } else {
        let sql = format!(
            "INSERT INTO PROGRESS (DEVICE_ID,DEVICE,PERCENTAGE,PROGRESS,DOCUMENT,TIMESTAMP,USER_ID) VALUES (?1,?2,?3,?4,?5,{},{});",
            timestamp, user_id
        );
        let save = db.prepare(sql);
        let exe = save.bind(&[
            device_id.into(),
            device.into(),
            percentage.into(),
            progress.into(),
            document.into(),
        ]);
        match exe {
            Ok(state) => match state.run().await {
                Ok(r) => {
                    if r.success() {
                         Response::builder()
                            .with_status(200)
                            .from_json(&serde_json::json!(
                                {
                                    "document":document,
                                    "timestamp":timestamp
                                }
                            ))
                    } else {
                        console_log!("插入失败，返回错误响应");
                         Ok(Response::builder().with_status(500).empty())
                    }
                }
                Err(e) => {
                    console_error!("sql执行失败：{}", e);
                     Ok(Response::builder().with_status(500).empty())
                }
            },
            Err(e) => {
                console_error!("sql语句处理失败：{}", e);
                 Ok(Response::builder().with_status(500).empty())
            }
        }
    }
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    let router = Router::new();
    router
        //注册账号
        .post_async("/users/create", |mut req, ctx| async move {
            console_log!("{:?}",ctx.env.var("DISABLE_REGISTER"));
            if let Ok(value) = ctx.env.var("DISABLE_REGISTER") {
                if value.to_string().eq_ignore_ascii_case("true") {
                   return Response::error("禁止注册", 405);
                }
            }
            let db = ctx.d1("koreader-sync").unwrap();
            register(&mut req, db).await
        })
        // 检验账号
        .get_async("/users/auth", |mut req, ctx| async move {
            let db = ctx.d1("koreader-sync").unwrap();
            authorize(&mut req, db).await
        })
        //更新进度
        .put_async("/syncs/progress", |mut req, ctx| async move {
            let db = ctx.d1("koreader-sync").unwrap();
            update_progress(&mut req, db).await
        })
        //获取进度
        .get_async("/syncs/progress/:document", |mut req, ctx| async move {
            if let Some(document) = ctx.param("document") {
                let db = ctx.d1("koreader-sync").unwrap();
                get_progress(&mut req, db, document).await
            } else {
                Response::error("参数异常", 404)
            }
        })
        // check
        .get_async("/", |_req, _ctx| async move { 
            let dt = js_sys::Date::new_0().to_locale_string("zh-CN",&JsValue::undefined());
            Response::ok(dt) 
        })
        .run(req, env)
        .await
}
