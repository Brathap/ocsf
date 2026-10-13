import React from 'react';
import { Composition } from 'remotion';
import { ULPFSentinelVideo } from './ULPFSentinelVideo';

export const RemotionRoot: React.FC = () => {
  return (
    <Composition
      id="ULPFSentinelDemo"
      component={ULPFSentinelVideo}
      durationInFrames={900}
      fps={30}
      width={1920}
      height={1080}
    />
  );
};
