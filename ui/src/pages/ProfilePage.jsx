import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import UserProfile from "../profile/UserProfile";

export default function ProfilePage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const requiresProfile = user?.profile_completed === false;

  useEffect(() => {
    if (user && user.profile_completed) {
      navigate("/dashboard", { replace: true });
    }
  }, [user, navigate]);

  return <UserProfile requiresProfile={requiresProfile} />;
}
