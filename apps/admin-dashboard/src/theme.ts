import { createTheme } from '@mantine/core';

const axis = [
  '#edf4ff',
  '#dceaff',
  '#b9d8ff',
  '#8db8ff',
  '#6fa7ff',
  '#4e8df2',
  '#3775df',
  '#285fd1',
  '#1c55cd',
  '#143d94',
] as const;

export const exaltoTheme = createTheme({
  fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif',
  fontFamilyMonospace: 'ui-monospace, "SFMono-Regular", "SF Mono", Menlo, monospace',
  headings: {
    fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", sans-serif',
    fontWeight: '600',
  },
  primaryColor: 'axis',
  defaultRadius: 'sm',
  colors: {
    axis: [...axis],
    verify: [...axis],
  },
  components: {
    ActionIcon: { defaultProps: { radius: 'sm' } },
    Badge: { defaultProps: { radius: 'sm' } },
    Button: { defaultProps: { radius: 'sm' } },
    Drawer: { defaultProps: { radius: 'md', overlayProps: { blur: 0 } } },
    Input: { defaultProps: { radius: 'sm' } },
    Menu: { defaultProps: { radius: 'sm' } },
    Modal: {
      defaultProps: {
        centered: true,
        radius: 'md',
        overlayProps: { blur: 0, backgroundOpacity: 0.32 },
        transitionProps: { transition: 'pop', duration: 160 },
      },
    },
    Paper: { defaultProps: { radius: 'sm', shadow: undefined } },
    Select: {
      defaultProps: {
        radius: 'sm',
        comboboxProps: { withinPortal: true, position: 'bottom-start' },
      },
    },
    SegmentedControl: { defaultProps: { radius: 'sm' } },
  },
});
