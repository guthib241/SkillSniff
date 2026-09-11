---
name: accessible-ui-review
description: Reviews a user interface for accessibility defects and returns prioritised fixes with the exact markup to change. Use when the user asks about accessibility, a11y, WCAG, screen readers, keyboard navigation, colour contrast, or focus management; when reviewing a component, form, modal, or page; or whenever the user asks whether an interface is usable by everyone.
license: MIT
metadata:
  version: 1.0.0
  category: ui
---

# Accessible UI review

Find accessibility defects that actually block people, and return the markup
that fixes them. Prefer a native element over an ARIA reconstruction of one.

## Rules

These must not be skipped, and no deadline pressure exempts them:

1. **Never claim a component is accessible because it has ARIA attributes.**
   ARIA on a `div` is usually a sign the wrong element was chosen. Check the
   element first.
2. **Every finding names the affected user.** "Keyboard-only users cannot
   dismiss this dialog" beats "missing keydown handler".
3. **Give the replacement markup, not a description of it.** A finding the
   reader has to translate into code is half a finding.
4. **Do not report contrast failures without the measured ratio** and the
   threshold it missed.
5. **Automated checks find a minority of real defects.** Never present a
   tooling pass as a completed review.

## Steps

1. **Identify the component's job.** What is the user trying to accomplish?
   Accessibility failures are failures of that job, not of a checklist.
2. **Check semantics first.** Is each interactive element a `button`, `a`,
   `input`, or `select`? Replace reconstructed controls with native ones
   before doing anything else; this dissolves most other findings.
3. **Walk the keyboard path.** Tab through in DOM order. Confirm every
   interactive element is reachable, the focus indicator is visible, focus is
   trapped inside modals and released on close, and `Escape` dismisses.
4. **Check the accessible name of every control.** Load
   `references/naming.md` for how names are computed and the common ways they
   come out empty or wrong.
5. **Check state and change announcements.** Loading, error, validation, and
   success states need to reach assistive technology, not just the pixels.
   Load `references/patterns.md` for live regions and disclosure patterns.
6. **Measure colour contrast** for text and for the focus indicator. Verify
   that colour is never the only carrier of meaning.
7. **Check motion, zoom, and target size.** Confirm the layout survives 200%
   zoom and 320px width, and that animation respects reduced-motion.
8. **Verify each finding before reporting it.** Re-read the source and make
   sure the element you cite is the element you described.

Track progress:

- [ ] Component job identified
- [ ] Semantics checked
- [ ] Keyboard path walked
- [ ] Accessible names checked
- [ ] State announcements checked
- [ ] Contrast measured
- [ ] Zoom and motion checked
- [ ] Findings verified against source

## Guardrails

Stop and ask the user when:

- The framework's rendered output is not visible and semantics cannot be
  confirmed from source alone.
- The design appears to require a pattern with no accessible equivalent. Say
  so plainly and propose an alternative interaction rather than inventing
  ARIA to paper over it.

Do not redesign the interface. Report accessibility defects and their fixes;
aesthetic opinions dilute the review and get it dismissed.

Do not recommend removing a focus outline under any circumstances. If the
default is unattractive, replace it with a visible alternative.

## Output

Order findings by how completely they block a user:

```
## Accessibility review: <component>

**Reviewed:** <what was examined>
**Not covered:** <what was excluded>

### <BLOCKER|SERIOUS|MODERATE> — <short title>

- **Who this blocks:** <the affected user and what they cannot do>
- **Location:** `path/to/Component.tsx:24`
- **Criterion:** <WCAG criterion, e.g. 2.4.7 Focus Visible (AA)>
- **Fix:**

  ```diff
  - <div class="btn" onclick="save()">Save</div>
  + <button type="button" onclick="save()">Save</button>
  ```

### What passed

<briefly, so the reader knows it was checked>
```

Worked example:

```
### BLOCKER — Icon-only close button has no accessible name

- **Who this blocks:** screen reader users, who hear only "button" and
  cannot tell what it does
- **Location:** `components/Dialog.tsx:41`
- **Criterion:** 4.1.2 Name, Role, Value (A)
- **Fix:**

  ```diff
  - <button onClick={close}><XIcon /></button>
  + <button onClick={close} aria-label="Close dialog"><XIcon aria-hidden="true" /></button>
  ```
```

## Caveats

- **The most common mistake is testing with a screen reader you know well.**
  Behaviour differs across pairings; note which you assumed.
- **`aria-hidden` on a focusable element creates a ghost stop**: reachable by
  keyboard, invisible to assistive technology. Watch for it on icons inside
  buttons.
- **Placeholder text is not a label.** It disappears on input and is often
  too low-contrast. This is a frequent false pass.
- **`tabindex` above zero is nearly always a defect.** It breaks the natural
  order and its effects compound across a page.
- A known pitfall is fixing the contrast of text while leaving the focus
  indicator below threshold. Measure both.
