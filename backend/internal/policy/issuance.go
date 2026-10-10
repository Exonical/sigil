package policy

import (
	"slices"

	"github.com/Exonical/sigil/backend/internal/db"
)

// IssuanceRequest asks whether the caller may have a certificate issued for a token.
// The certificate identity always comes from the token's assigned user, never from the caller.
type IssuanceRequest struct {
	Roles        []string
	Station      db.Station
	Token        *db.Token
	UserID       string
	ProfileRoles []string
}

// AuthorizeIssuance allows a station operator to enroll any assigned active token at a station,
// and allows the assigned user to enroll their own token when one of their roles is in the profile's roles.
func AuthorizeIssuance(request IssuanceRequest) Decision {
	if request.Station.Status != "active" {
		return Decision{Reason: "station is not active"}
	}
	if request.Token == nil {
		return Decision{Reason: "token is not in inventory"}
	}
	if request.Token.Status != "active" {
		return Decision{Reason: "token is not active"}
	}
	if request.Token.AssignedUserID == nil {
		return Decision{Reason: "token is not assigned to a user"}
	}
	if request.Station.Mode == "station" &&
		(hasRole(request.Roles, "admin") || hasRole(request.Roles, "helpdesk")) {
		return Decision{Allowed: true, Reason: "station operator authorized"}
	}
	if *request.Token.AssignedUserID == request.UserID &&
		slices.ContainsFunc(request.ProfileRoles, func(role string) bool {
			return hasRole(request.Roles, role)
		}) {
		return Decision{Allowed: true, Reason: "self-service enrollment authorized for assigned token"}
	}
	return Decision{Reason: "user is not authorized to enroll a certificate on this token"}
}

// ProfileVisible reports whether the caller's roles allow a profile without considering a token.
func ProfileVisible(roles, profileRoles []string) bool {
	return slices.ContainsFunc(profileRoles, func(role string) bool {
		return hasRole(roles, role)
	})
}
