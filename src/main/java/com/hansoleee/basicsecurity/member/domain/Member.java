package com.hansoleee.basicsecurity.member.domain;

import lombok.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "tn_member")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@ToString
@EqualsAndHashCode(of = "email")
public class Member {

    @Id
    @Column(name = "member_id")
    private String email;

    private String password;
}
