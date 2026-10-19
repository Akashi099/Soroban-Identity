import React, { useEffect, useState } from "react";

export interface ViewTransitionProps {
  viewKey: string;
  children: React.ReactNode;
  className?: string;
}

export const ViewTransition: React.FC<ViewTransitionProps> = ({
  viewKey,
  children,
  className = "",
}) => {
  const [transitioning, setTransitioning] = useState(false);

  useEffect(() => {
    setTransitioning(true);
    const timer = setTimeout(() => {
      setTransitioning(false);
    }, 200);
    return () => clearTimeout(timer);
  }, [viewKey]);

  return (
    <div
      key={viewKey}
      className={`view-transition-container fade-in ${transitioning ? "view-transition-enter" : ""} ${className}`.trim()}
    >
      {children}
    </div>
  );
};

export default ViewTransition;
