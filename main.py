from fastapi import FastAPI, File, UploadFile, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from jose import JWTError, jwt
import models
import database
import auth
import cloudinary
import cloudinary.uploader
import os



models.Base.metadata.create_all(bind=database.engine)

app = FastAPI()

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
)


class RegisterRequest(BaseModel):
    email: EmailStr
    pseudo: str
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

@app.post("/register")
def register(req: RegisterRequest, db: Session = Depends(database.get_db)):
    if db.query(models.User).filter(models.User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email déjà utilisé")

    user = models.User(
        email=req.email,
        pseudo=req.pseudo,
        password_hash=auth.hash_password(req.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "Utilisateur créé avec succès", "id": user.id}

@app.post("/login")
def login(req: LoginRequest, db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == req.email).first()
    if not user or not auth.verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Identifiants incorrects")

    token = auth.create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer", "user": {"id": user.id, "pseudo": user.pseudo}}

@app.get("/me")
def me(token: str, db: Session = Depends(database.get_db)):
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        user_id = int(payload.get("sub"))
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    return {"id": user.id, "email": user.email, "pseudo": user.pseudo}

@app.get("/init-db")
def init_db():
    models.Base.metadata.create_all(bind=database.engine)
    return {"message": "Tables créées ✅"}

@app.post("/upload")
def upload_image(
    file: UploadFile = File(...),
    token: str = None,
    db: Session = Depends(database.get_db)
):
    # Vérifie le token de l'utilisateur
    user_data = auth.verify_token(token, db)
    user_id = user_data["user_id"]

    # Envoie l’image vers Cloudinary
    try:
        upload_result = cloudinary.uploader.upload(
            file.file,
            folder=f"user_{user_id}/",
            unique_filename=True,
            overwrite=False
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur upload Cloudinary : {e}")

    # Sauvegarde dans la base
    new_image = models.Photo(
        user_id=user_id,
        url=upload_result["secure_url"],
        public_id=upload_result["public_id"]
    )
    db.add(new_image)
    db.commit()

    return {"message": "Image uploadée ✅", "url": upload_result["secure_url"]}

@app.get("/")
def root():
    return {"message": "API en ligne 🚀"}
