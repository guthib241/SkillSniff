# State, announcements and common patterns

## Live regions

Content that changes without a page navigation must be announced.

| Situation | Approach |
| --- | --- |
| Validation error appears | `aria-live="assertive"`, or move focus to the error summary |
| Search results update | `aria-live="polite"` on the results count |
| Toast or snackbar | `role="status"` (polite) or `role="alert"` (assertive) |
| Progress or loading | `aria-busy="true"` on the region, plus a polite status message |

The live region must exist in the DOM before the content changes. Injecting
the region and its message together often announces nothing.

Reserve assertive for cases that genuinely interrupt. Overuse makes the
interface unusable.

## Form validation

- Associate the error with the field via `aria-describedby`.
- Set `aria-invalid="true"` on the failing field.
- Do not rely on colour alone for the error state.
- On submit failure, move focus to a summary listing each error as a link to
  its field.

## Disclosure and menus

- The trigger carries `aria-expanded` reflecting real state.
- `aria-controls` points at the id of the region it toggles.
- Content that is visually hidden must also be hidden from assistive
  technology, or it becomes a ghost tab stop.

## Modal dialogs

A correct dialog does all of the following. Missing any one is a blocker:

1. Focus moves into the dialog on open.
2. Focus is trapped while it is open.
3. `Escape` closes it.
4. Focus returns to the trigger on close.
5. Background content is inert (`inert` attribute, or `aria-hidden` on the
   background plus blocked pointer events).
6. It has an accessible name, usually via `aria-labelledby` on its heading.

Prefer the native `<dialog>` element with `showModal()`, which provides most
of this without reconstruction.

## Contrast thresholds

| Content | AA | AAA |
| --- | --- | --- |
| Body text | 4.5:1 | 7:1 |
| Large text (18.66px bold, or 24px) | 3:1 | 4.5:1 |
| UI components and graphical objects | 3:1 | — |
| Focus indicator against adjacent colour | 3:1 | — |

Measure against the actual rendered background, including any gradient,
image, or overlay behind the text.
