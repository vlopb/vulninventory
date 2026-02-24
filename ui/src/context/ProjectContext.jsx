import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { useAuth } from "./AuthContext";
import { API_BASE, authFetch, unwrapItems } from "../utils/api";

const ProjectContext = createContext(null);

export function ProjectProvider({ children }) {
  const { user } = useAuth();
  const isAuthenticated = Boolean(user);
  const [orgs, setOrgs] = useState([]);
  const [projects, setProjects] = useState([]);
  const [orgId, setOrgId] = useState(() => localStorage.getItem("vi_selectedOrg") || "");
  const [projectId, setProjectId] = useState(() => localStorage.getItem("vi_selectedProject") || "");

  useEffect(() => {
    if (orgId) {
      localStorage.setItem("vi_selectedOrg", orgId);
    } else {
      localStorage.removeItem("vi_selectedOrg");
    }
  }, [orgId]);

  useEffect(() => {
    if (projectId) {
      localStorage.setItem("vi_selectedProject", projectId);
    } else {
      localStorage.removeItem("vi_selectedProject");
    }
  }, [projectId]);

  const fetchOrgs = useCallback(async () => {
    if (!isAuthenticated) {
      setOrgs([]);
      setOrgId("");
      return;
    }
    try {
      const resp = await authFetch(`${API_BASE}/orgs`);
      if (resp.ok) {
        const data = await resp.json();
        setOrgs(unwrapItems(data));
      }
    } catch (error) {
      console.error("Error loading orgs:", error);
    }
  }, [isAuthenticated]);

  const fetchProjects = useCallback(async (oid) => {
    if (!oid) {
      setProjects([]);
      setProjectId("");
      return;
    }
    try {
      const resp = await authFetch(`${API_BASE}/orgs/${oid}/projects`);
      if (resp.ok) {
        const data = await resp.json();
        setProjects(unwrapItems(data));
      }
    } catch (error) {
      console.error("Error loading projects:", error);
    }
  }, []);

  const createOrg = useCallback(async (name) => {
    const resp = await authFetch(`${API_BASE}/orgs`, {
      method: "POST",
      body: JSON.stringify({ name }),
    });
    if (!resp.ok) {
      throw new Error("Error creating org");
    }
    const data = await resp.json();
    setOrgs((prev) => [...prev, data]);
    setOrgId(String(data.id));
    return data;
  }, []);

  const createProject = useCallback(async (oid, name) => {
    const resp = await authFetch(`${API_BASE}/orgs/${oid}/projects`, {
      method: "POST",
      body: JSON.stringify({ name }),
    });
    if (!resp.ok) {
      throw new Error("Error creating project");
    }
    const data = await resp.json();
    setProjects((prev) => [...prev, data]);
    setProjectId(String(data.id));
    return data;
  }, []);

  useEffect(() => {
    fetchOrgs();
  }, [fetchOrgs]);

  useEffect(() => {
    if (orgId) {
      fetchProjects(orgId);
    }
  }, [orgId, fetchProjects]);

  useEffect(() => {
    if (orgs.length > 0 && !orgId) {
      setOrgId(String(orgs[0].id));
    }
  }, [orgs, orgId]);

  const value = {
    orgs,
    setOrgs,
    fetchOrgs,
    createOrg,
    projects,
    setProjects,
    fetchProjects,
    createProject,
    orgId,
    setOrgId,
    projectId,
    setProjectId,
  };

  return <ProjectContext.Provider value={value}>{children}</ProjectContext.Provider>;
}

export function useProject() {
  const ctx = useContext(ProjectContext);
  if (!ctx) {
    throw new Error("useProject must be used within ProjectProvider");
  }
  return ctx;
}
